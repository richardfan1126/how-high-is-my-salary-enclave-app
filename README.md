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

The enclave app is built using the GitHub Action workflow. It is triggered automatically when changes inside `enclaves/` are pushed to the `main` branch.

The build output is an [EIF file](https://docs.aws.amazon.com/enclaves/latest/user/building-eif.html), stored in the GitHub Container Registry under the same repository.

E.g. `ghcr.io/richardfan1126/how-high-is-my-salary-enclave-app:538f821a3cacf8370a4a707f79fc26476bc27bb6`

If you want to customize the enclave app, you can fork this repository and push the changes to the `main` branch of the forked repository.

You can skip this step if you choose to use the EIF file I built.

### (Optional) Verify the artifact

This step verifies whether the EIF file is indeed built using the trusted source code and build environment, which is crucial to ensuring software integrity.

However, if you are sure the EIF file is not being tampered with or if you are just playing with this project, you may skip this step.

The software artifacts are stored in the GitHub Container Registry, which we can access on the `Packages` page of the repository.

   ![Packages page can be access through the link on the right-side](/docs/images/51f1ae1a-0441-4d3b-ab64-5fc252187770.png)

The artifact is tagged by the commit SHA hash. Note that the tags with the prefix `sha256-` are the artifact signatures and attestations, not the software artifacts.

Each artifact is signed/attested by 3 different methods. The verification steps are as follows:

_(You can choose one to perform depending on you requirements):_

* Cosign signature

   <details>
   
   1. Install cosign
   
      Read: https://docs.sigstore.dev/system_config/installation/

   1. Run the following command

      ```bash
      cosign verify <artifact_uri> \
          --certificate-oidc-issuer https://token.actions.githubusercontent.com \
          --certificate-identity "<github_action_workflow_ref>" \
          --certificate-github-workflow-repository "<github_repo_name>"
      ```

      E.g.
      ```bash
      cosign verify ghcr.io/richardfan1126/how-high-is-my-salary-enclave-app:538f821a3cacf8370a4a707f79fc26476bc27bb6 \
          --certificate-oidc-issuer https://token.actions.githubusercontent.com \
          --certificate-identity "https://github.com/richardfan1126/how-high-is-my-salary-enclave-app/.github/workflows/build-and-sign-eif.yaml@refs/heads/main" \
          --certificate-github-workflow-repository "richardfan1126/how-high-is-my-salary-enclave-app"
      ```

      If the artifact is signed using the correct GitHub Action workflow, you will see the following message.

      ```
      Verification for <artifact_uri> --
      The following checks were performed on each of these signatures:
      - The cosign claims were validated
      - Existence of the claims in the transparency log was verified offline
      - The code-signing certificate was verified using trusted certificate authority certificates
      ```

      You will also see the JSON object containing the signing certificate details.

   Learn more at: https://docs.sigstore.dev/verifying/verify/
   </details>

* GitHub Artifact Attestations

   <details>

   1. Install GitHub CLI

      Read: https://github.com/cli/cli#installation

   1. Login to GitHub CLI with your GitHub account

      Read: https://cli.github.com/manual/gh_auth_login

   1. Run the following command

      ```bash
      gh attestation verify oci://<artifact_uri> \
          --owner <repo_owner_username>
      ```

      E.g.

      ```bash
      gh attestation verify oci://ghcr.io/richardfan1126/how-high-is-my-salary-enclave-app:538f821a3cacf8370a4a707f79fc26476bc27bb6 \
          --owner richardfan1126
      ```

      If the artifact is correctly attested by the correct GitHub Action workflow, you will see the following message.

      ```
      ✓ Verification succeeded!
      ```

      If you want to see the attestation detail, add a flag `--format json` to the command.

      E.g.

      ```bash
      gh attestation verify oci://ghcr.io/richardfan1126/how-high-is-my-salary-enclave-app:538f821a3cacf8370a4a707f79fc26476bc27bb6 \
          --owner richardfan1126 \
          --format json
      ```

   Learn more at: https://docs.github.com/en/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds
   </details>

* SLSA GitHub Generator

   <details>

   1. Install `slsa-verifier`

      Read: https://github.com/slsa-framework/slsa-verifier#installation

   1. Run the following commands

      ```bash
      ./slsa-verifier verify-image <artifact_uri> \
          --source-uri <github_repo_url>
      ```

      **NOTE:** `<artifact_uri>` must contain the digest (i.e. `@sha256:123456...`)

      E.g.

      ```bash
      ./slsa-verifier verify-image ghcr.io/richardfan1126/how-high-is-my-salary-enclave-app:538f821a3cacf8370a4a707f79fc26476bc27bb6@sha256:7f2d906d9290ad68e60786e5267d99759cf4098e8fcfc28de49cc69e9bfaf447 \
          --source-uri github.com/richardfan1126/how-high-is-my-salary-enclave-app
      ```

      If the artifact is correctly attested by the correct GitHub Action workflow, you will see the following message.

      ```
      Verified build using builder "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.0.0" at commit 0123456789abcdef0123456789abcdef01234567
      PASSED: Verified SLSA provenance
      ```

      To view the [SLSA provenance](https://slsa.dev/spec/v0.2/provenance) of the build, run the following commands

      _You will need cosign for the following commands. Read the installation step [here](https://docs.sigstore.dev/system_config/installation/)_

      ```bash
      cosign download attestation <artifact_uri> \
         | jq -r '.payload' \
         | base64 -d \
         | jq
      ```

      E.g.

      ```bash
      cosign download attestation ghcr.io/richardfan1126/how-high-is-my-salary-enclave-app:538f821a3cacf8370a4a707f79fc26476bc27bb6 \
         | jq -r '.payload' \
         | base64 -d \
         | jq
      ```
   </details>

### Obtain PCR values of the EIF

[PCR](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-concepts.html#term-pcr) is the measurement of the EIF file.

These are the values that the client app uses to verify whether it's communicating with the genuine enclave app.

The PCR values of the EIF we've just built can be obtained from the artifact annotation.

1. Go to the detail page of the artifact

   E.g., https://github.com/richardfan1126/how-high-is-my-salary-enclave-app/pkgs/container/how-high-is-my-salary-enclave-app/237830213

1. Scroll down to `Manifest`, you will see `PCR0`, `PCR1`, and `PCR2`.

   E.g.

   ```json
   {
       ...
       "labels": {
           "PCR0": "0b3b6546969f7e2d692fe7ca2bab0273cb10ed3ea4bcf5e292d95f68e5149058ea2b4d569dbdcb3fea2d3ed7e85dc73a",
           "PCR1": "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
           "PCR2": "6e03fd3eacec687eb88046102dcb3bdcd0ea422fbc5ce8844a9ebf122ecae3c373264ebfcf6775b93ef04c912d9bc215",
           ...
       }
   }
   ```

   For our project, the client app only validates the `PCR0` value, so take note of it.

### Deploy the enclave app

To deploy the enclave app, deploy the Terraform stack inside `terraform/`

1. Install terraform CLI

   Read: https://developer.hashicorp.com/terraform/install

1. Modify `terraform.tfvars`

   Change `eif_artifact_path` to the EIF artifact URI on GitHub Container Registry.

   You can skip this step if you choose to use the EIF file I built.

1. Setup your AWS account credential on CLI

   Read: https://registry.terraform.io/providers/hashicorp/aws/latest/docs#authentication-and-configuration

1. Apply terraform stack

   Run the following commands

   ```bash
   cd terraform/
   terraform init
   terraform apply
   ```

   Review the resources to be created, and type `yes` to confirm.

1. Take note of the EC2 instance public IP address

   The IP address will be shown on your CLI as the terraform output `instance_public_ip`.

### Run client app

To interact with the enclave app, we can use the Python client app inside `client/`.

To use the app, you need Python 3.10 or above.

1. (Optional) Create a virtual environment

   You can create a virtual environment for the client app to avoid mixing dependencies' versions with your global Python setup.

   ```bash
   cd client/
   python3 -m venv .venv/
   source .venv/bin/activate
   ```

1. Install dependencies

   ```bash
   pip install -r requirements.txt
   ```

1. Modify `config.ini`

   Change the values as follows:

   * **PCR0**: Change to the `PCR0` value you take from the **Obtain PCR values of the EIF** step.

   * **EnclaveEndpoint**: Change to the public IP address of the EC2 instance you have deployed in the **Deploy the enclave app** step.

1. Run the app

   ```bash
   python main.py
   ```
