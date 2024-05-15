# How high is my salary enclave app

This simple app showcases how to protect software supply chain security using GitHub Actions, SLSA, and AWS Nitro Enclaves.

## Scenario

We always want to know how high (or low) our salary is compared to that of our colleagues, friends, or family. To do that, we need one person to collect everyone’s salary and rank them.

However, we don’t want to expose our exact salary, so finding a trustworthy person to be the data collector is always challenging. 

In the computer system environment, this problem can be separated as follows:

* Users want to know the software's source code (i.e., business logic).

   _To ensure no backdoor sending your salary out and selling it._

* Users want to know if the system they interact with is the same as the source code they have just seen.

   _To ensure it's not malware emulating the real software._

* No one should have access to the data stored in the system

   _To ensure no one can dump the system memory and extract our salary data._

## Components

This app has 4 major components.

### AWS Nitro Enclaves

[AWS Nitro Enclaves](https://aws.amazon.com/ec2/nitro/nitro-enclaves/) is a Trusted Execution Environment running on AWS EC2 instances.

It is an isolated environment with no admin access, persistent memory, or external network connection, which minimizes the risk of data exfiltration and system tampering.

AWS Nitro Enclaves also provides [Attestation Document](https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html), a digitally signed document describing the running enclave. By presenting this document to the client app, end-users can verify if the enclave is running the expected software.

In this project, the enclave will run an API server written in Rust (inside the `enclave/`). The app will collect the salaries of different users and rank them.

### Artifact build, signing, and attestation

To ensure the enclave app's build is not tampered, we use [GitHub Actions](https://docs.github.com/en/actions) to build the app (workflow definition inside `.github/workflows/build-and-sign-eif.yaml`). GitHub-hosted runners provide a hardened, isolated environment for us to build the software, ensuring the integrity of the software artifact.

To prove the integrity of the build, we will also attest and sign the artifact.

To showcase different artifact attestation and signing methods, this project utilized the following process:

* Simply signing using [Sigstore](https://docs.sigstore.dev/signing/signing_with_containers/)

* Attest using [GitHub Artifact Attestations](https://github.blog/2024-05-02-introducing-artifact-attestations-now-in-public-beta/)

* Attest using [SLSA GitHub Generator](https://github.blog/2022-04-07-slsa-3-compliance-with-github-actions/)

Each method gives users different levels of assurance about the software artifact.

### Terraform

To deploy the enclave app we have built, there is a Terraform template inside `terraform/`.

This template creates an AWS EC2 instance that runs the Enclave app and accepts incoming API traffic from the client.

### Client app

To interact with the enclave app, we can use the Python client app inside `client/`.

Besides handling API communication, this app also handles the Nitro Enclave attestation document verification and traffic encryption. This ensures end-users interact with the real application running in AWS Nitro Enclaves. Their data is also kept confidential between the client app and the enclave.

## How to use this app

### (Optional) Build the enclave app

### Verify the build

### Deploy the enclave app

### Run client app
