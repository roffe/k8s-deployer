from __future__ import print_function
import json
import logging
import os
import tempfile
import time
import subprocess
import zipfile
import datetime
from configparser import RawConfigParser
from itertools import chain
from base64 import b64decode, b64encode
from jinja2 import Environment, FileSystemLoader

import boto3
import urllib3
import yaml
# from botocore.client import Config as botoConfig
from kubernetes import client as k8sclient
from kubernetes import config as k8sconfig
from kubernetes.client.rest import ApiException
from urllib3.exceptions import NewConnectionError

deploy_start_time = int(time.time())
logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.info('Logging initialized')

# Get Environment config variables
try:
    REGION_NAME = os.environ['AWS_REGION']
    DEPLOY_CONFIG_BUCKET = os.environ['DEPLOY_CONFIG_BUCKET']
    DEPLOY_CONFIG_FOLDER = os.environ['DEPLOY_CONFIG_FOLDER']
    DOCKER_REGISTRY = os.environ['DOCKER_REGISTRY']
    APP_CONFIG_BUCKET = os.environ['APP_CONFIG_BUCKET']
except Exception as e:
    logger.critical("Missing ENV variable %s", e)
    raise e

DEFAULT_TIMEOUT = '5'

# Determine if running locally or in AWS
try:
    SAM_LOCAL = os.environ['SAM_LOCAL']
    logger.setLevel(logging.ERROR)
except Exception as e:
    SAM_LOCAL = None

# get slack url from env, decrypt with kms
HOOK_URL = (
    "https://",
    boto3.client(
        'kms',
        region_name=REGION_NAME
    ).decrypt(
        CiphertextBlob=b64decode(
            os.environ['SLACK_HOOK_URL']
        )
    )['Plaintext'].decode('utf-8')
)
s3 = boto3.resource('s3')
code_pipeline = boto3.client('codepipeline', region_name=REGION_NAME)

# Disable urllib3 warnings
urllib3.disable_warnings()


def slackColor(status):
    # define a default color
    color = "#439FE0"  # blue
    bad_status = ["CANCELED", "FAILED", "STOPPED"]
    warning_status = [
        "RESUMED", "IN_PROGRESS", "SUPERSEDED", "STARTED", "WARNING"
    ]
    good_status = ["SUCCEEDED", "DONE", "SUCCESSFUL"]
    if any(x in status for x in bad_status):
        color = 'danger'
    if any(x in status for x in warning_status):
        color = 'warning'
    if any(x in status for x in good_status):
        color = 'good'

    return color


def send_slack(name, status, message, event):
    # logger.info("%s %s %s", name, status, message)

    event_type = ""

    if "CodePipeline.job" in event:
        deploy_id = event["CodePipeline.job"]["id"]
        event_type = "CodePipeline"

    if "SGNRunDeploy.job" in event:
        deploy_id = "Manual"
        event_type = "SGNRunDeploy"

    color = slackColor(status)

    slack_message = {
        'ts': str(deploy_start_time),
        "attachments": [
            {
                "fallback": "sgn-{p} {m} ({t} ID: {d_id}) {s}".format(
                    s=status,
                    p=name,
                    d_id=deploy_id,
                    t=event_type,
                    m=message
                ),
                "color": "{color}".format(color=color),
                "text": "*sgn-{project}* {message} _{status}_".format(
                    status=status,
                    project=name,
                    message=message
                ),
                "footer": "{} ID: {}".format(event_type, deploy_id)
            }
        ]
    }

    http = urllib3.PoolManager()

    try:
        if SAM_LOCAL != "true":
            http.request(
                'POST', ''.join(HOOK_URL),
                headers={'Content-Type': 'application/json'},
                body=json.dumps(slack_message).encode('utf-8')
            )
    except Exception as e:
        logger.error(e)

    try:
        if (status == "FAILED"):
            if "CodePipeline.job" in event:
                code_pipeline.put_job_failure_result(
                    jobId=event['CodePipeline.job']['id'],
                    failureDetails={
                        'message': 'Job Failed',
                        'type': 'JobFailed'
                    }
                )
        if status == "SUCCESSFUL":
            if "CodePipeline.job" in event:
                code_pipeline.put_job_success_result(
                    jobId=event['CodePipeline.job']['id']
                )
    except Exception as e:
        logger.error(e)


def inplace_change(filename, o_s, n_s):
    with open(filename) as f:
        s = f.read()
        if o_s not in s:
            return

    with open(filename, 'w') as f:
        s = s.replace(o_s, n_s)
        f.write(s)


def create_namespace(k8s_client, namespace):
    api_instance = k8sclient.CoreV1Api(api_client=k8s_client)

    ns = k8sclient.V1Namespace(
        metadata=k8sclient.V1ObjectMeta(name=namespace)
    )

    try:
        api_instance.create_namespace(ns)
        logger.info("Namespace \"%s\" created", namespace)
    except ApiException as e:
        if e.status == 409:
            logger.info("Namespace \"%s\" aready exists", namespace)
        else:
            raise e


def create_secret(k8s_client, deploy_name, deployspec, deploy_env, tmpdir):
    deploy_config = "{}/{}/{}".format(deploy_name, deploy_env, "config")
    try:
        s3.meta.client.download_file(
            APP_CONFIG_BUCKET,
            deploy_config,
            tmpdir+'/config'
        )
    except Exception as e:
        logger.error("Could not get config from s3 %s", e)
        raise e

    if os.path.isfile(tmpdir+'/config'):
        parser = RawConfigParser()
        with open(tmpdir+'/config') as lines:
            lines = chain(("[config]",), lines)
            parser.read_file(lines)

        metadata = {
                    'name': deploy_name.replace('_', '-') + '-' + deploy_env,
                    'namespace': deployspec['namespace'],
                    'labels': {
                        'sgn-app': deploy_name.replace('_', '-')
                        }
                    }
        data = {}
        for key, value in parser.items('config'):
            value = value.strip('"')
            value = value.strip("'")
            data[key.upper()] = b64encode(
                str(value).encode('utf-8')
            ).decode('ascii')
        secretBody = k8sclient.V1Secret(
            'v1',
            data,
            'Secret',
            metadata,
            type='Opaque'
        )
        k8s = k8sclient.CoreV1Api(api_client=k8s_client)
        try:
            k8s.create_namespaced_secret(
                deployspec['namespace'],
                secretBody,
                _request_timeout=DEFAULT_TIMEOUT
            )
            logger.info("Created secret {}/{}".format(
                deployspec['namespace'],
                metadata['name']
                )
            )
        except ApiException as e:
            if e.status == 409:
                k8s.replace_namespaced_secret(
                    deploy_name.replace('_', '-') + '-' + deploy_env,
                    deployspec['namespace'],
                    secretBody,
                    _request_timeout=DEFAULT_TIMEOUT
                )
                logger.info("Replaced secret {}/{}".format(
                    deployspec['namespace'],
                    metadata['name']
                    )
                )
            else:
                raise e


def injectEnv(dep, deployName, deploy_env, deployspec):
    containers = dep['spec']['template']['spec']['containers']
    for i, container in enumerate(containers):
        if 'env' not in container:
            containers[i]['env'] = list()
        containers[i]['env'].append(
            {
                'name': 'DEPLOY_TS',
                'value': "{}".format(time.time())
            }
        )
        containers[i]['env'].append(
            {
                'name': 'AWS_METADATA_SERVICE_TIMEOUT',
                'value': "5"
            }
        )
        containers[i]['env'].append(
            {
                'name': 'COMMITREF',
                'value': deployspec['commitref']
            }
        )
        containers[i]['env'].append(
            {
                'name': 'AWS_METADATA_SERVICE_NUM_ATTEMPTS',
                'value': "20"
            }
        )
        containers[i]['env'].append(
            {
                'name': 'APPLICATION_NAME',
                'value': deployName
            }
        )
        containers[i]['env'].append(
            {
                'name': 'DEPLOYMENT_GROUP_NAME',
                'value': deploy_env
            }
        )
        containers[i]['env'].append(
            {
                'name': 'MY_NODE_NAME',
                'valueFrom': {
                    'fieldRef': {
                        'fieldPath': 'spec.nodeName'
                    }
                }
            }
        )
        containers[i]['env'].append(
            {
                'name': 'MY_POD_NAME',
                'valueFrom': {
                    'fieldRef': {
                        'fieldPath': 'metadata.name'
                    }
                }
            }
        )
        containers[i]['env'].append(
            {
                'name': 'MY_POD_IP',
                'valueFrom': {
                    'fieldRef': {
                        'fieldPath': 'status.podIP'
                    }
                }
            }
        )
        containers[i]['env'].append(
            {
                'name': 'MY_CPU_REQUEST',
                'valueFrom': {
                    'resourceFieldRef': {
                        'containerName': containers[i]['name'],
                        'resource': 'requests.cpu'
                    }
                }
            }
        )
        containers[i]['env'].append(
            {
                'name': 'MY_CPU_LIMIT',
                'valueFrom': {
                    'resourceFieldRef': {
                        'containerName': containers[i]['name'],
                        'resource': 'limits.cpu'
                    }
                }
            }
        )
        containers[i]['env'].append(
            {
                'name': 'MY_MEM_REQUEST',
                'valueFrom': {
                    'resourceFieldRef': {
                        'containerName': containers[i]['name'],
                        'resource': 'requests.memory'
                    }
                }
            }
        )
        containers[i]['env'].append(
            {
                'name': 'MY_MEM_LIMIT',
                'valueFrom': {
                    'resourceFieldRef': {
                        'containerName': containers[i]['name'],
                        'resource': 'limits.memory'
                    }
                }
            }
        )

    dep['spec']['template']['spec']['containers'] = containers

    if 'envsecret' in deployspec:
        if deployspec['envsecret'] is True:
            for containers_list in ('containers', 'initContainers'):
                if containers_list in dep['spec']['template']['spec']:
                    containers = dep['spec']['template']['spec'][containers_list]
                    for i, container in enumerate(containers):
                        if 'envFrom' not in container:
                            containers[i]['envFrom'] = list()
                        containers[i]['envFrom'].append({
                            'secretRef': {
                                'name': deployName.replace('_', '-') + '-' + deploy_env
                            }
                        })
                    dep['spec']['template']['spec'][containers_list] = containers

    return dep


def injectAnnotation(dep, deployspec):
    if "metadata" not in dep:
        dep['metadata'] = {}

    if "annotations" not in dep['metadata']:
        dep['metadata']['annotations'] = {}

    dep['metadata']['annotations']['kubernetes.io/change-cause'] = "{} {}".format(
        deployspec['commitref'],
        datetime.datetime.now()
    )

    return dep


def create_deployment(client, deployName, deploy_env, deployspec, yamlPath):
    if os.path.isfile(yamlPath):
        inplace_change(
            yamlPath,
            'SGN_DEPLOY_IMAGE',
            "{}/{}:{}".format(
                DOCKER_REGISTRY,
                deployName,
                deployspec['commitref']
            )
        )
        dep = yaml.load(open(yamlPath, 'r'))
        k8s = k8sclient.AppsV1Api(api_client=client)
        dep = injectEnv(dep, deployName, deploy_env, deployspec)
        dep = injectAnnotation(dep, deployspec)
        try:
            k8s.create_namespaced_deployment(
                body=dep,
                namespace=deployspec['namespace'],
                _request_timeout=DEFAULT_TIMEOUT)
            logger.info("Deployment \"%s\" created", dep["metadata"]["name"])
        except NewConnectionError as e:
            logger.critical('Connection error')
            raise e
        except ApiException as e:
            if e.status == 409:
                k8s.replace_namespaced_deployment(
                    name=dep["metadata"]["name"],
                    namespace=deployspec['namespace'],
                    body=dep,
                    _request_timeout=DEFAULT_TIMEOUT)
                logger.info(
                    "Deployment \"%s\" replaced",
                    dep["metadata"]["name"]
                )
            else:
                raise e


def create_stateful(k8s_client, deployName, deploy_env, deployspec, yamlSrc):
    if os.path.isfile(yamlSrc):
        inplace_change(
            yamlSrc,
            'SGN_DEPLOY_IMAGE',
            "{}/{}:{}".format(
                DOCKER_REGISTRY,
                deployName,
                deployspec['commitref']
            )
        )
        dep = yaml.load(open(yamlSrc, 'r'))
        k8s = k8sclient.AppsV1Api(api_client=k8s_client)
        dep = injectEnv(dep, deployName, deploy_env, deployspec)
        dep = injectAnnotation(dep, deployspec)
        try:
            k8s.create_namespaced_stateful_set(
                body=dep,
                namespace=deployspec['namespace'],
                _request_timeout=DEFAULT_TIMEOUT)
            logger.info("Stateful set \"%s\" created", dep["metadata"]["name"])
        except NewConnectionError as e:
            logger.critical('Connection error')
            raise e
        except ApiException as e:
            if e.status == 409:
                k8s.replace_namespaced_stateful_set(
                    name=dep["metadata"]["name"],
                    namespace=deployspec['namespace'],
                    body=dep,
                    _request_timeout=DEFAULT_TIMEOUT)
                logger.info(
                    "Stateful set \"%s\" replaced",
                    dep["metadata"]["name"]
                )
            else:
                raise e


def create_service(k8s_client, deployspec, service_yaml):
    if os.path.isfile(service_yaml):
        k8s = k8sclient.CoreV1Api(api_client=k8s_client)
        try:
            svc = yaml.load(open(service_yaml, 'r'))
            k8s.create_namespaced_service(
                deployspec['namespace'],
                svc,
                _request_timeout=DEFAULT_TIMEOUT)
            logger.info("Service \"%s\" created", svc["metadata"]["name"])
        except ApiException as e:
            if e.status == 409:
                k8s.patch_namespaced_service(
                    svc["metadata"]["name"],
                    deployspec['namespace'],
                    svc,
                    _request_timeout=DEFAULT_TIMEOUT
                )
                logger.info("Service \"%s\" patched", svc["metadata"]["name"])
            else:
                raise e


def create_configmap(k8s_client, deployspec, configmap_yaml):
    if os.path.isfile(configmap_yaml):
        k8s = k8sclient.CoreV1Api(api_client=k8s_client)
        try:
            cm = yaml.load(open(configmap_yaml, 'r'))
            k8s.create_namespaced_config_map(
                deployspec['namespace'],
                cm,
                _request_timeout=DEFAULT_TIMEOUT)
            logger.info("Configmap \"%s\" created", cm["metadata"]["name"])
        except ApiException as e:
            if e.status == 409:
                k8s.replace_namespaced_config_map(
                    cm["metadata"]["name"],
                    deployspec['namespace'],
                    cm,
                    _request_timeout=DEFAULT_TIMEOUT
                )
                logger.info("Configmap \"%s\" replaced", cm["metadata"]["name"])
            else:
                raise e


def getAcmFromDeployspec(deployspec, cluster_name):
    retval = ""
    if 'acm' in deployspec.keys():
        for i in range(len(deployspec["acm"])):
            if 'cluster' in deployspec["acm"][i]:
                if cluster_name in deployspec["acm"][i]["cluster"]:
                    retval = deployspec["acm"][i]["arn"]
    return retval


def create_ingress(k8s_client, deploy_env, deployspec, srcYaml, cluster):
    if os.path.isfile(srcYaml):
        ingress_raw = open(srcYaml).read()
        if 'SGN_DEPLOY_ENV' in ingress_raw:
            inplace_change(srcYaml, 'SGN_DEPLOY_ENV', deploy_env)
        if 'SGN_DEPLOY_ACM' in ingress_raw:
            inplace_change(
                srcYaml,
                'SGN_DEPLOY_ACM',
                getAcmFromDeployspec(deployspec, cluster['name'])
            )
        if 'SGN_CLUSTER_NAME' in ingress_raw:
            inplace_change(srcYaml, 'SGN_CLUSTER_NAME', cluster['name'])
        k8s = k8sclient.ExtensionsV1beta1Api(api_client=k8s_client)
        try:
            ing = yaml.load(open(srcYaml, 'r'))
            k8s.create_namespaced_ingress(
                deployspec['namespace'],
                ing,
                _request_timeout=DEFAULT_TIMEOUT)
            logger.info("Ingress \"%s\" created", ing["metadata"]["name"])
        except ApiException as e:
            if e.status == 409:
                k8s.patch_namespaced_ingress(
                    ing["metadata"]["name"],
                    deployspec['namespace'],
                    ing,
                    _request_timeout=DEFAULT_TIMEOUT
                )
                logger.info("Ingress \"%s\" patched", ing["metadata"]["name"])
            else:
                raise e


def create_cron(k8s_client, deployspec, cron_yaml):
    if os.path.isfile(cron_yaml):
        k8s = k8sclient.BatchV1beta1Api(api_client=k8s_client)
        try:
            cron = yaml.load(open(cron_yaml, 'r'))
            k8s.create_namespaced_cron_job(
                deployspec['namespace'],
                cron,
                _request_timeout=DEFAULT_TIMEOUT)
            logger.info("Cron \"%s\" created", cron["metadata"]["name"])
        except ApiException as e:
            if e.status == 409:
                k8s.replace_namespaced_cron_job(
                    cron["metadata"]["name"],
                    deployspec['namespace'],
                    cron,
                    _request_timeout=DEFAULT_TIMEOUT
                )
                logger.info("Cron \"%s\" replaced", cron["metadata"]["name"])
            else:
                raise e


def create_servicemonitor(tmpdirname, servicemonitor_yaml):
    if os.path.isfile(servicemonitor_yaml):
        dep = yaml.load(open(servicemonitor_yaml, 'r'))
        logger.info("Creating {} {}".format(
            dep['kind'],
            dep["metadata"]["name"]
            )
        )
        kubeconf = tmpdirname+"/kubeconf"
        command = [
            "bin/kubectl", "--kubeconfig",
            kubeconf, "-n", dep["metadata"]["namespace"],
            "apply", "-f", servicemonitor_yaml
        ]
        try:
            res = subprocess.check_output(command, timeout=450)
        except Exception as e:
            message = "_{kind}_ *{name}* error creating: {msg} ".format(
                kind=dep['kind'],
                name=dep["metadata"]["name"],
                msg=e,
            )
            send_slack(dep["metadata"]["name"], "WARNING", message, event)
            logger.error(e)
            # raise(e)
        logger.info(res)


def create_pdb(k8s_client, deployspec, pdb_yaml):
    if os.path.isfile(pdb_yaml):
        k8s = k8sclient.PolicyV1beta1Api(api_client=k8s_client)

        pdb = yaml.load(open(pdb_yaml, 'r'))
        body = k8sclient.V1beta1PodDisruptionBudget(
            api_version=pdb['apiVersion'],
            kind=pdb['kind'],
            metadata=pdb['metadata'],
            spec=pdb['spec'],
        )
        try:
            k8s.create_namespaced_pod_disruption_budget(
                deployspec['namespace'],
                body,
                _request_timeout=DEFAULT_TIMEOUT,
                async=True
            )
            logger.info("PDB \"%s\" created", pdb["metadata"]["name"])
        except ApiException as e:
            if e.status == 409:
                k8s.replace_namespaced_pod_disruption_budget(
                    pdb["metadata"]["name"],
                    deployspec['namespace'],
                    body,
                    _request_timeout=DEFAULT_TIMEOUT
                )
                logger.info("PDB \"%s\" replaced", pdb["metadata"]["name"])
            else:
                raise e


def runManualDeploy(event, tmpdirname):
    """
    {
        "SGNRunDeploy.job": {
            "Application": "k8s-hello-world",
            "envFrom": "k8s-staging",
            "envTo": "k8s-staging"
        }
    }
    """
    from boto3.dynamodb.conditions import Key
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table('kubernetes_deploy')

    details = event['SGNRunDeploy.job']

    appCond = Key('Application').eq(details['Application'])
    envCond = Key('Env').eq(details['envFrom'])

    response = table.query(
        KeyConditionExpression=appCond & envCond
    )
    data = response['Items']

    postGraphite(details['Application'], details['envTo'], event, 'start')

    for item in data:
        deployFromDB(item, event, tmpdirname)

    postGraphite(details['Application'], details['envTo'], event, 'start')


def rolloutStatus(tmpdirname, spec, namespace, event):
    dep = yaml.load(open(tmpdirname + '/' + spec, 'r'))
    logger.info("Rolling out {} {}".format(
        dep['kind'],
        dep["metadata"]["name"]
        )
    )
    kubeconf = tmpdirname+"/kubeconf"
    message = "Rolling out _{kind}_ *{name}*".format(
        kind=dep['kind'],
        name=dep["metadata"]["name"]
    )
    send_slack(dep["metadata"]["name"], "IN_PROGRESS", message, event)
    command = [
        "bin/kubectl", "--kubeconfig",
        kubeconf, "-n", namespace,
        "rollout", "status",
        dep['kind'], dep["metadata"]["name"]
    ]

    try:
        result = subprocess.check_output(command, timeout=300)
    except Exception as e:
        message = "_{kind}_ *{name}* error rolling out!\n*Manually rollback the {kind} to restore it!\n error: {msg} ".format(
            kind=dep['kind'],
            name=dep["metadata"]["name"],
            msg=e,
        )
        send_slack(dep["metadata"]["name"], "FAILED", message, event)
        raise(e)

    lines = result.decode("utf-8")
    logger.info("%s", lines)
    message = "_{kind}_ *{name}* successfully rolled out".format(
        kind=dep['kind'],
        name=dep["metadata"]["name"],
    )
    send_slack(dep["metadata"]["name"], "DONE", message, event)


def setlastDeploy(name, env, bucketName, objectKey, tag):
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table('kubernetes_deploy')
    table.put_item(
       Item={
            'Application': name,
            'Env': env,
            'Deployed': "{time}".format(time=time.time()),
            'objectKey': objectKey,
            'bucketName': bucketName,
            'Tag': tag
        }
    )


def checkDeployspec(tmpdirname):
    if os.path.isfile(tmpdirname+'/deployspec.yml'):
        deployspec = yaml.load(open(tmpdirname+'/deployspec.yml'))
        if 'commitref' not in deployspec:
            raise Exception("Missing commitref in deployspec!")
    else:
        raise Exception("Missing deployspec.yml\nPlease see DEPLOYSPEC.md")
    return deployspec


def getKubeConfigFromS3(deploy_env, tmpdirname):
    kubeConfigS3obj = DEPLOY_CONFIG_FOLDER + '/' + deploy_env + '/config'
    print("Debug S3 kubectl '{}' '{}' '{}'".format(
        DEPLOY_CONFIG_BUCKET,
        kubeConfigS3obj,
        tmpdirname+'/kubeconf'
    ))
    try:
        s3.meta.client.download_file(
            DEPLOY_CONFIG_BUCKET,
            kubeConfigS3obj,
            tmpdirname+'/kubeconf'
        )
    except Exception as e:
        raise Exception('Error getting kubectl config from s3: {}'.format(
            str(e)
            ))


def getDeployZipFromS3(from_bucket, from_key, tmpdirname):
    try:
        s3.meta.client.download_file(
            from_bucket, from_key,
            tmpdirname+'/deploy.zip'
        )
    except Exception as e:
        raise Exception('Error getting deploy artifact from s3: {}'.format(
            str(e)
            ))

    try:
        zip_ref = zipfile.ZipFile(tmpdirname+'/deploy.zip', 'r')
        zip_ref.extractall(tmpdirname)
        zip_ref.close()
    except Exception as e:
        raise Exception('Error extracting zip: {}'.format(
            str(e)
            ))


def runDeploySpec(deploy_name, dep, deploy_env, event, tmpdir):
    client = k8sconfig.new_client_from_config(config_file=tmpdir+'/kubeconf')
    _, active_context = k8sconfig.list_kube_config_contexts(
        config_file=tmpdir+'/kubeconf'
    )
    try:
        if dep['envsecret'] is True:
            use_secenv = True
        else:
            use_secenv = None
    except Exception as e:
        use_secenv = None

    # Create namespace
    create_namespace(client, dep['namespace'])

    # render the deploy templates
    renderTemplates(active_context, deploy_name, deploy_env, dep, tmpdir)

    if use_secenv:
        try:
            create_secret(client, deploy_name, dep, deploy_env, tmpdir)
        except Exception as e:
            msg = "Error creating secret: {}".format(e)
            send_slack(deploy_name, "WARNING", msg, event)
            logger.error("Failed to create secret: %s", e)
            use_secenv = None

    # Create Configmap
    if "configmap" in dep['spec']:
        if isinstance(dep['spec']['configmap'], (list, tuple)):
            for s in dep['spec']['configmap']:
                create_configmap(client, dep, tmpdir + '/' + s)
        else:
            create_configmap(
                client,
                dep,
                tmpdir + '/' + dep['spec']['configmap']
            )

    # Create Service
    if "service" in dep['spec']:
        if isinstance(dep['spec']['service'], (list, tuple)):
            for s in dep['spec']['service']:
                create_service(client, dep, tmpdir + '/' + s)
        else:
            create_service(client, dep, tmpdir + '/' + dep['spec']['service'])

    # Create Stateful Service
    if "stateful_service" in dep['spec']:
        if isinstance(dep['spec']['stateful_service'], (list, tuple)):
            for s in dep['spec']['stateful_service']:
                create_service(client, dep, tmpdir + '/' + s)
        else:
            create_service(
                client, dep,
                tmpdir + '/' + dep['spec']['stateful_service']
            )

    # Create Deployment
    if "deploy" in dep['spec']:
        if isinstance(dep['spec']['deploy'], (list, tuple)):
            for s in dep['spec']['deploy']:
                create_deployment(
                    client, deploy_name, deploy_env,
                    dep, tmpdir + '/' + s
                )
                rolloutStatus(
                    tmpdir,
                    s,
                    dep['namespace'],
                    event
                )
        else:
            create_deployment(
                client, deploy_name, deploy_env,
                dep, tmpdir + '/' + dep['spec']['deploy']
            )
            rolloutStatus(
                tmpdir,
                dep['spec']['deploy'],
                dep['namespace'],
                event
            )
    # Create extra Deployment
    if "extra_deploy" in dep['spec']:
        if isinstance(dep['spec']['extra_deploy'], (list, tuple)):
            for s in dep['spec']['extra_deploy']:
                create_deployment(
                    client, deploy_name, deploy_env,
                    dep, tmpdir + '/' + s
                )
                rolloutStatus(
                    tmpdir,
                    s,
                    dep['namespace'],
                    event
                )
        else:
            create_deployment(
                client, deploy_name, deploy_env,
                dep, tmpdir + '/' + dep['spec']['extra_deploy']
            )
            rolloutStatus(
                tmpdir, dep['spec']['extra_deploy'], dep['namespace'], event
            )

    # Create Stateful Set
    if "stateful" in dep['spec']:
        if isinstance(dep['spec']['stateful'], (list, tuple)):
            for s in dep['spec']['stateful']:
                create_stateful(
                    client, deploy_name, deploy_env,
                    dep, tmpdir + '/' + s
                )
                rolloutStatus(
                    tmpdir,
                    s,
                    dep['namespace'],
                    event
                )
        else:
            create_stateful(
                client, deploy_name, deploy_env,
                dep, tmpdir + '/' + dep['spec']['stateful']
            )
            rolloutStatus(
                tmpdir,
                dep['spec']['stateful'],
                dep['namespace'],
                event
            )

    # Create Ingress
    if "ingress" in dep['spec']:
        if isinstance(dep['spec']['ingress'], (list, tuple)):
            for s in dep['spec']['ingress']:
                create_ingress(
                    client, deploy_env, dep,
                    tmpdir + '/' + s,
                    active_context
                )
        else:
            create_ingress(
                client, deploy_env, dep,
                tmpdir + '/' + dep['spec']['ingress'],
                active_context
            )

    if "cron" in dep['spec']:
        if 'cron_env' in dep['spec']:
            if deploy_env in dep['spec']['cron_env']:
                if isinstance(dep['spec']['cron'], (list, tuple)):
                    for s in dep['spec']['cron']:
                        create_cron(client, dep, tmpdir + '/' + s)
                else:
                    create_cron(
                        client,
                        dep,
                        tmpdir + '/' + dep['spec']['cron']
                    )
        else:
            send_slack(
                deploy_name,
                "WARNING",
                "missing 'cron_env' in deployspec.yml, please update!",
                event
            )

    # Create pdb
    if "pdb" in dep['spec']:
        if isinstance(dep['spec']['pdb'], (list, tuple)):
            for s in dep['spec']['pdb']:
                create_pdb(client, dep, tmpdir + '/' + s)
        else:
            create_pdb(client, dep, tmpdir + '/' + dep['spec']['pdb'])

    # Create pdb
    if "servicemonitor" in dep['spec']:
        if isinstance(dep['spec']['servicemonitor'], (list, tuple)):
            for s in dep['spec']['servicemonitor']:
                create_servicemonitor(tmpdir, tmpdir + '/' + s)
        else:
            create_servicemonitor(
                tmpdir,
                tmpdir + '/' + dep['spec']['servicemonitor']
            )


def deployFromDB(item, event, tmpdirname):
    details = event['SGNRunDeploy.job']
    deploy_name = details['Application']
    deploy_env = details['envTo']
    from_bucket = item['bucketName']
    from_key = item['objectKey']
    send_slack(
        deploy_name,
        "IN_PROGRESS",
        "Deployment from *{envFrom}* to *{envTo}*".format(
            envFrom=details['envFrom'],
            envTo=details['envTo']
            ),
        event
        )
    try:
        getKubeConfigFromS3(deploy_env, tmpdirname)
        getDeployZipFromS3(from_bucket, from_key, tmpdirname)
        dep = checkDeployspec(tmpdirname)
        # Deploy the spec
        runDeploySpec(deploy_name, dep, deploy_env, event, tmpdirname)
        # Update DynamoDB table
        setlastDeploy(
            deploy_name, deploy_env, from_bucket, from_key, dep['commitref']
        )
        # Tag docker image
        tagImage(deploy_name, dep['commitref'], deploy_env)
        # Deploy was successful, report to slack
        send_slack(
            deploy_name, "SUCCESSFUL",
            "Deployment to *{env}*".format(
                name=deploy_name,
                env=deploy_env
            ),
            event
        )
    except Exception as e:
        send_slack(deploy_name, "FAILED", str(e), event)
        raise e


def postGraphite(deploy_name, deploy_env, event, etype):

    if "CodePipeline.job" in event:
        deploy_id = event["CodePipeline.job"]["id"]

    if "SGNRunDeploy.job" in event:
        deploy_id = "Manual"

    url = 'http://graphite-new.int.shopgun.net:8080/events/'
    post_fields = {
        "what": deploy_name,
        "tags": [
            "deploy",
            deploy_name,
            deploy_env,
            "deploy-{}".format(etype)
        ],
        "data": "Deployment: {}".format(deploy_id)
    }

    http = urllib3.PoolManager()

    try:
        http.request(
            'POST', url,
            headers={'Content-Type': 'application/json'},
            body=json.dumps(post_fields).encode('utf-8')
        )
    except Exception as e:
        logger.error(e)


def handleCodePipeline(event, tmpdirname):
    # Extract attributes passed in by CodePipeline
    # job_id = event['CodePipeline.job']['id']
    job_data = event['CodePipeline.job']['data']
    artifact = job_data['inputArtifacts'][0]
    config = job_data['actionConfiguration']['configuration']
    # credentials = job_data['artifactCredentials']
    from_bucket = artifact['location']['s3Location']['bucketName']
    from_key = artifact['location']['s3Location']['objectKey']
    # from_revision = artifact['revision']
    deploy_name = config['UserParameters'].split('/')[0]
    deploy_env = config['UserParameters'].split('/')[1]
    postGraphite(deploy_name, deploy_env, event, 'start')
    # Temporary credentials to access CodePipeline artifact in S3
    # key_id = credentials['accessKeyId']
    # key_secret = credentials['secretAccessKey']
    # session_token = credentials['sessionToken']
    # artifact_session = boto3.Session(
    #    aws_access_key_id=key_id,
    #    aws_secret_access_key=key_secret,
    #    aws_session_token=session_token)

    send_slack(deploy_name, "IN_PROGRESS", "Deployment", event)

    try:
        getKubeConfigFromS3(deploy_env, tmpdirname)
        getDeployZipFromS3(from_bucket, from_key, tmpdirname)
        dep = checkDeployspec(tmpdirname)
        # Deploy the spec
        runDeploySpec(deploy_name, dep, deploy_env, event, tmpdirname)
        # Update DynamoDB table
        setlastDeploy(
            deploy_name, deploy_env, from_bucket, from_key, dep['commitref']
        )
        # Tag docker image
        tagImage(deploy_name, dep['commitref'], deploy_env)
        # Deploy was successful, report to slack
        send_slack(
            deploy_name,
            "SUCCESSFUL",
            "Deploy to *{env}*".format(
                env=deploy_env
            ),
            event
        )

    except Exception as e:
        send_slack(deploy_name, "FAILED", str(e), event)
        raise e

    postGraphite(deploy_name, deploy_env, event, 'end')
    return "Completed"


def tagImage(repository, tag, newtag):
    from botocore.exceptions import ClientError
    client = boto3.client('ecr', region_name=REGION_NAME)
    sts_client = boto3.client("sts", region_name=REGION_NAME)
    account_id = sts_client.get_caller_identity()["Account"]

    response = client.batch_get_image(
        registryId=account_id,
        repositoryName=repository,
        imageIds=[
            {
                'imageTag': tag
            },
        ]
    )
    try:
        response = client.put_image(
            registryId=account_id,
            repositoryName=repository,
            imageManifest=response['images'][0]['imageManifest'],
            imageTag=newtag
        )
    except ClientError as e:
        if e.response['Error']['Code'] != 'ImageAlreadyExistsException':
            raise


def renderTemplates(cluster, deploy_name, deploy_env, deployspec, tmpdir):
    deploy_image = "{}/{}:{}".format(
        DOCKER_REGISTRY,
        deploy_name,
        deployspec['commitref']
    )
    clustername = cluster['name']
    j2_env = Environment(
        loader=FileSystemLoader(tmpdir),
        lstrip_blocks=True,
        trim_blocks=True
    )
    values = {}
    if 'templating' in deployspec:
        if clustername in deployspec['templating']:
            values = deployspec['templating'][clustername]

    for tmpl_v, tmpl_f in deployspec['spec'].items():
        if str(tmpl_v) == 'cron_env':
            continue
        logger.info("Rendering %s", tmpl_v)
        if isinstance(tmpl_f, (list, tuple)):
            for s in tmpl_f:
                template = j2_env.get_template(s).render(
                    values,
                    cluster_name=clustername,
                    deploy_env=deploy_env,
                    namespace=deployspec['namespace'],
                    deploy_image=deploy_image,
                    docker_tag=deployspec['commitref'],
                    project=deploy_name
                )
                filename = tmpdir + '/' + s
                with open(filename, "w") as fh:
                    logger.info(template)
                    fh.write(template)
        else:
            template = j2_env.get_template(tmpl_f).render(
                values,
                cluster_name=clustername,
                deploy_env=deploy_env,
                namespace=deployspec['namespace'],
                deploy_image=deploy_image,
                docker_tag=deployspec['commitref'],
                project=deploy_name
            )
            filename = tmpdir + '/' + tmpl_f
            with open(filename, "w") as fh:
                logger.info(template)
                fh.write(template)


def get_my_log_stream(context):
    print("Log stream name:", context.log_stream_name)
    print("Log group name:",  context.log_group_name)
    print("Request ID:", context.aws_request_id)
    print("Mem. limits(MB):", context.memory_limit_in_mb)
    time.sleep(1)
    print("Time remaining (MS):", context.get_remaining_time_in_millis())


def lambda_handler(event, context):
    logger.info("Event: %s", str(event))
    logger.info(
        "Time remaining (MS): %d",
        context.get_remaining_time_in_millis()
    )
    if "SGNRunDeploy.job" in event:
        with tempfile.TemporaryDirectory() as tmpdirname:
            runManualDeploy(event, tmpdirname)

    if "CodePipeline.job" in event:
        with tempfile.TemporaryDirectory() as tmpdirname:
            handleCodePipeline(event, tmpdirname)

    return "Success"
