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

E.g. `ghcr.io/richardfan1126/how-high-is-my-salary-enclave-app:f088278396d8c4d914a871ccacecd7fb497a958c`

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
   
      See: https://docs.sigstore.dev/system_config/installation/

   1. Run the following command

      ```bash
      cosign verify <artifact_uri> \
          --certificate-identity-regexp "<github_repo_url>" \
          --certificate-oidc-issuer https://token.actions.githubusercontent.com
      ```

      E.g.
      ```bash
      cosign verify ghcr.io/richardfan1126/how-high-is-my-salary-enclave-app:f088278396d8c4d914a871ccacecd7fb497a958c \
          --certificate-identity-regexp "https://github.com/richardfan1126/how-high-is-my-salary-enclave-app/" \
          --certificate-oidc-issuer https://token.actions.githubusercontent.com
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

      See: https://github.com/cli/cli#installation

   1. Login to GitHub CLI with your GitHub account

      See: https://cli.github.com/manual/gh_auth_login

   1. Run the following command

      ```bash
      gh attestation verify oci://<artifact_uri> \
          --owner <repo_owner_username>
      ```

      E.g.

      ```bash
      gh attestation verify oci://ghcr.io/richardfan1126/nitro-enclaves-cosign-sandbox:94a13386dbce65ebd079aad4183930d8155ba087 \
          --owner richardfan1126
      ```

      If the artifact is correctly attested by the correct GitHub Action workflow, you will see the following message.

      ```
      ✓ Verification succeeded!
      ```

      If you want to see the attestation detail, add a flag `--format json` to the command.

      E.g.

      ```bash
      gh attestation verify oci://ghcr.io/richardfan1126/nitro-enclaves-cosign-sandbox:94a13386dbce65ebd079aad4183930d8155ba087 \
          --owner richardfan1126 \
          --format json
      ```

   Learn more at: https://docs.github.com/en/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds
   </details>

* SLSA GitHub Generator

   <details>

   1. Install `slsa-verifier`

      See: https://github.com/slsa-framework/slsa-verifier#installation

   1. Run the following commands

      ```bash
      ./slsa-verifier verify-image <artifact_uri> \
          --source-uri <github_repo_url>
      ```

      **NOTE:** `<artifact_uri>` must contain the digest (i.e. `@sha256:123456...`)

      E.g.

      ```bash
      ./slsa-verifier verify-image ghcr.io/richardfan1126/how-high-is-my-salary-enclave-app:f088278396d8c4d914a871ccacecd7fb497a958c@sha256:aa299150fcabde6ef4c67c59eeab14b58222e572eb97927e12842a69ef9bb43a \
          --source-uri github.com/richardfan1126/how-high-is-my-salary-enclave-app
      ```

      If the artifact is correctly attested by the correct GitHub Action workflow, you will see the following message.

      ```
      Verified build using builder "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.0.0" at commit 0123456789abcdef0123456789abcdef01234567
      PASSED: Verified SLSA provenance
      ```
   </details>

### Obtain PCR values of the EIF

[PCR](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-concepts.html#term-pcr) is the measurement of the EIF file.

These are the values that the client app uses to verify whether it's communicating with the genuine enclave app.

The PCR values of the EIF we've just built can be obtained from the artifact annotation.

1. Go to the detail page of the artifact

   E.g., https://github.com/richardfan1126/how-high-is-my-salary-enclave-app/pkgs/container/how-high-is-my-salary-enclave-app/215966914

1. Scroll down to `Manifest`, you will see `PCR0`, `PCR1`, and `PCR2`.

   E.g.

   ```json
   {
       ...
       "labels": {
           "PCR0": "86a197e809c78a6ce144b6a961e039e494470ac395ed1033b704c05ffe43b9dd0974ff138c2420ac66dd5b0d01599495",
           "PCR1": "52b919754e1643f4027eeee8ec39cc4a2cb931723de0c93ce5cc8d407467dc4302e86490c01c0d755acfe10dbf657546",
           "PCR2": "77ab86ccb92fd7e526edb30e8b61cd934c2d07be07b9a6c582ebc8dc2613def9427761b2206371a39e31b10392aeeba6",
           ...
       }
   }
   ```

   For our project, the client app only validates the `PCR0` value, so take note of it.

### Deploy the enclave app

### Run client app
