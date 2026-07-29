# Lab 0: Environment Setup Report

**Name:** Muhammad Asyraf bin Aznan

**Student ID:** 52215124467

**Subject:** Cloud Computing Security Essentials

**Code:** IKB 42603

**Date:** 30 July 2027

---

## Purpose

This report documents the local development environment setup and verification for Windows 11. The accompanying screenshots serve as evidence of each completed step.

## Requirements

- At least 16 GB RAM
- More than 10 GB available storage space

---

## Step 1: Install Docker

Docker was installed from the official Docker website ([https://www.docker.com](https://www.docker.com)). During installation, WSL2 was selected when prompted as the backend engine.

After installation, the version was verified from the command prompt:

```text
docker --version
Docker version 29.6.2, build dfc4efb
```

A test container was run to confirm Docker can pull and execute images:

```text
docker run --rm hello-world
```

Output confirmed:

```text
Hello from Docker!
This message shows that your installation appears to be working correctly.
```

**Result:** Docker Engine 29.6.2 is installed and can pull and run containers successfully.

**Evidence:**

![Picture1](/Lab0-Assets/Picture1.png)
![Picture2](/Lab0-Assets/Picture2.png)

---

## Step 2: Install AWS CLI

The AWS Command Line Interface (CLI) v2 was downloaded and installed from:

```
https://awscli.amazonaws.com/AWSCLIV2-3.14.6.msi
```

The installed version was verified from the command prompt:

```text
aws --version
aws-cli/2.36.9 Python/3.14.6 Windows/11 exe/AMD64
```

**Result:** AWS CLI v2 (version 2.36.9) is installed and accessible from the command line.

**Evidence:**

![Picture3](/Lab0-Assets/Picture3.png)

---

## Step 3: Install kind and kubectl

The Kubernetes-in-Docker (`kind`) tool and the Kubernetes command-line client (`kubectl`) were installed using Chocolatey (`choco`) via the command prompt.

Versions were verified as follows:

```text
C:\Users\User>kind version
kind v0.23.0 go1.21.10 windows/amd64

C:\Users\User>kubectl version --client
Client Version: v1.30.0
Kustomize Version: v5.0.4-0.20230601165947-6ce0bf390ce3
```

**Result:** Both `kind` (v0.23.0) and `kubectl` (v1.30.0) are installed and ready for local Kubernetes cluster management.

**Evidence:**

![Picture4](/Lab0-Assets/Picture4.png)

---

## Step 4: Install Helper Tools (Git Bash & OpenSSL)

Git Bash was installed from the official Git website:

```
https://git-scm.com/install/windows
```

Git Bash provides a Unix-like terminal (MINGW64) for running lab shell commands. OpenSSL is bundled with Git Bash and was verified:

```text
openssl version
OpenSSL 3.5.4 30 Sep 2025 (Library: OpenSSL 3.5.4 30 Sep 2025)
```

**Result:** Git Bash and OpenSSL 3.5.4 are available and operational as the helper terminal environment.

**Evidence:**

![Picture5.1](/Lab0-Assets/Picture5.1.png)

---

## Step 5: Start and Stop the Lab Environment

### 5a. Local AWS (LocalStack)

LocalStack was started in Docker, exposing port `4566` (AWS services) and port `5678`:

```text
docker run -d --name localstack -p 4566:4566 -p 5678:5678 -v /var/lib/localstack localstack/localstack:4.14.0
2ac17534e83444f9e8d987dba9c9bb08b5fe00d7affa964f8f993bb056ef30f9
```

The health endpoint was checked to confirm all LocalStack services are available:

```text
curl http://localhost:4566/_localstack/health
```

Output showed all services — including `acm`, `apigateway`, `cloudformation`, `cloudwatch`, `config`, `dynamodb`, `ec2`, `iam`, `kms`, `lambda`, `logs`, `opensearch`, `redshift`, `route53`, `s3`, `s3control`, `ses`, `sns`, `sqs`, `sts`, `support`, `swf`, `transcribe` — all reporting `"available"`, with edition `"community"` and version `"4.14.0"`.

The container lifecycle was also tested:

```text
docker stop localstack
localstack

docker start localstack
localstack

docker rm -f localstack
localstack
```

**Result:** LocalStack 4.14.0 is running as a Docker container. Its AWS-compatible local service endpoint is healthy and the container lifecycle (stop, start, remove) works correctly.

**Evidence:**

![Picture6](/Lab0-Assets/Picture6.png)
![Picture7](/Lab0-Assets/Picture7.png)
![Picture8](/Lab0-Assets/Picture8.png)
![Picture9.1](/Lab0-Assets/Picture9.1.png)
![Picture10](/Lab0-Assets/Picture10.png)
![Picture11](/Lab0-Assets/Picture11.png)

---

### 5b. Local Kubernetes Cluster (kind)

The installed versions of `kind` and `kubectl` were first confirmed in CMD:

```text
C:\Users\User>kind version
kind v0.23.0 go1.21.10 windows/amd64

C:\Users\User>kubectl version --client
Client Version: v1.30.0
Kustomize Version: v5.0.4-0.20230601165947-6ce0bf390ce3
```

A local Kubernetes cluster named `ccse` was then created using `kind`:

```text
C:\Users\User>kind create cluster --name ccse
Creating cluster "ccse" ...
 • Ensuring node image (kindest/node:v1.30.0) ...
 ✓ Ensuring node image (kindest/node:v1.30.0)
 • Preparing nodes ...
 ✓ Preparing nodes
 • Writing configuration ...
 ✓ Writing configuration
 • Starting control-plane ...
 ✓ Starting control-plane
 • Installing CNI ...
 ✓ Installing CNI
 • Installing StorageClass ...
 ✓ Installing StorageClass
Set kubectl context to "kind-ccse"
You can now use your cluster with:

kubectl cluster-info --context kind-ccse

Have a nice day! 👋
```

The cluster was verified with:

```text
C:\Users\User>kubectl cluster-info --context kind-ccse kubectl get nodes
Kubernetes control plane is running at https://127.0.0.1:22931
CoreDNS is running at https://127.0.0.1:22931/api/v1/namespaces/kube-system/services/kube-dns:dns/proxy

To further debug and diagnose cluster problems, use 'kubectl cluster-info dump'.
```

Output confirmed the Kubernetes control plane is running at `https://127.0.0.1:22931` and CoreDNS is available.

The cluster was then removed as part of the lifecycle test:

```text
C:\Users\User>kind delete cluster --name ccse
Deleting cluster "ccse" ...
Deleted nodes: ["ccse-control-plane"]
```

**Result:** A local Kubernetes cluster can be created, accessed, inspected, and deleted successfully using `kind`.

**Evidence:**

![Picture18](/Lab0-Assets/Picture18.png)
![Picture17](/Lab0-Assets/Picture17.png)
![Picture14](/Lab0-Assets/Picture14.png)
![Picture15](/Lab0-Assets/Picture15.png)
![Picture16](/Lab0-Assets/Picture16.png)

---

## Step 6: One-Time AWS CLI Configuration for LocalStack

The AWS CLI was configured with LocalStack test credentials and a default region. Commands were run in CMD (Command Prompt):

```text
C:\Users\User>aws configure set aws_access_key_id test

C:\Users\User>aws configure set aws_secret_access_key test

C:\Users\User>aws configure set region us-east-1
```

An endpoint variable was set to point to LocalStack:

```text
C:\Users\User>set EP=--endpoint-url=http://localhost:4566
```

The connection was verified using AWS STS:

```text
C:\Users\User>aws %EP% sts get-caller-identity
```

The command returned the LocalStack test identity:

```json
{
    "UserId": "AKIAIOSFODNN7EXAMPLE",
    "Account": "000000000000",
    "Arn": "arn:aws:iam::000000000000:root"
}
```

**Result:** The AWS CLI is configured correctly to communicate with LocalStack instead of a live AWS account.

**Evidence:**

![Picture12](/Lab0-Assets/Picture12.png)
![Picture13](/Lab0-Assets/Picture13.png)

---

## Conclusion

The required Lab 0 environment has been fully set up and verified on Windows 11. The following tools are confirmed operational:

| Tool | Version | Status |
|---|---|---|
| Docker | 29.6.2 | Installed |
| AWS CLI | 2.36.9 | Installed |
| kind | 0.23.0 | Installed |
| kubectl | v1.30.0 | Installed |
| OpenSSL (Git Bash) | 3.5.4 | Installed |
| LocalStack | 4.14.0 | Running |
| AWS CLI (LocalStack config) | — | Configured |
| Local Kubernetes cluster (kind) | — | Created & Deleted |

All environment components required for the lab are in place and functioning correctly.
