+++
title = 'Automate Postman Secret Scanning With Trufflehog'
summmary = ''
date = 2024-04-26T09:55:12-04:00
draft = false
+++

## Introduction

Unintentional secret exposure on the internet is a problem as old as the internet itself. While `hunter2` may not have been the first password to be inadvertently shared for everyone to see, it has certainly not been the last. Since then, a significant number of new websites and tools have been released that make it even easier to accidentally disclose credentials, including passwords, private keys, API keys, and more. Some websites, such as Pastebin and its various clones, have been used to maliciously leak dumps of this information. Others, like GitHub are taking active steps to detect and alert on these credentials to prevent their misuse. Lately, I have been working with a team researching scanning for secrets in Postman.

## Common Sources of Secrets in Postman

Postman offers a number of ways to manage data used in making API calls. Some of this is protected, but much of it is not. The most common sources of credentials are the request headers and environment variables. However, credentials can easily be found in a number of other places as well.

<!-- TODO: Figure for Overview tab -->

{{< figure src="/images/postman/environment.png" alt="A screenshot of part of the variables section of the environment tab in Postman" caption="Environment Variables" >}}

{{< figure src="/images/postman/params.png" alt="A screenshot of part of the Params tab in a request in Postman" caption="Params" >}}

{{< figure src="/images/postman/authorization.png" alt="A screenshot of part of the Authorization tab in a request in Postman" caption="Authorization" >}}

{{< figure src="/images/postman/headers.png" alt="A screenshot of part of the Headers tab in a request in Postman" caption="Headers" >}}

<!-- TODO: Figure for Body tab -->

{{< figure src="/images/postman/pre-request-script.png" alt="A screenshot of part of the Pre-request Script tab in a request in Postman" caption="Params" >}}

## Starting the Automation Process

However, there is an easier way to get this information in a programatic way: using the Postman API. If you know the request ID of your target request, you can get the JSON data directly without an API key.

{{< figure src="/images/postman/api.png" alt="A screenshot of the Postman API output of a request" caption="Postman API" >}}

This means that we can start with a file including a list of unique URLs found on the Postman network and filter out the ones that have request IDs:

```
cat unique_urls.json |jq -r .[] > urls
grep "/request/" urls > requests
```

Then we can modify those URLs to use the Postman API syntax:

{{< figure src="/images/postman/requests.png" alt="A screenshot a file containing a list of Postman API requests" caption="Postman API Request URLs" >}}

Fetch all of these URLs using your favorite tool, save them locally, and now you can use Trufflehog to scan for secrets in these request files.

{{< figure src="/images/postman/trufflehog-filesystem.png" alt="A screenshot of a number of Trufflehog verified secrets" caption="Verified Secrets" >}}

This workflow is great, but we can go a step further and automate the process of fetching request IDs.

## Automating the Search

There are two ways to automate the search on Postman; however, it is worth noting that both methods are limited to 200 (ish) results. This means that more specific search terms will provide better results with a smaller number of requests hidden by this cap.

{{< figure src="/images/postman/ws-search.png" alt="A screenshot of a request and response in Caido showing the parameters for the Web Socket method" caption="Method 1: Websockets (POST https://web.postman.co/_api/ws/proxy)" >}}

Using the Postman websockets API allows for a machine-friendly way to automatically gather data. This works well as long as Postman supports it and allows it to be used.

{{< figure src="/images/postman/selenium-search.png" alt="A screenshot of the Selenium driven workflow method" caption="Method 2: Selenium" >}}

If (or when) the Postman websockets API becomes inaccessible for any reason, you can use Selenium or other browser automation tools that are typically used for integration testing to navigate the Postman website for you and extract relevant data.

## Optimizing the Search

In order to maximize the signal-to-noise ratio in a search in an attempt to stay below the results cap where possible, our team has created a tool that fetches domains that are in-scope for bug bounty programs: [devcoinfet/postman_research](https://github.com/devcoinfet/postman_research).

{{< figure src="/images/postman/postman_research-tool.png" alt="A screenshot of the files and README of the postman_research GitHub repository" caption="Postman scraping and parsing tooling" >}}

This still has room for improvement in terms of reducing noise further; however, the tooling has already resulted in a number of reported findings.

## Coming Soon: Even More Automation

Recently, Truffle Security released a post on this subject ([Postman Carries Lots of Secrets](https://trufflesecurity.com/blog/postman-carries-lots-of-secrets)) that details an additional tool we can use: using `trufflehog` to directly search target workspaces. At the time of writing, I have not been able to get this command to work, but will definitely keep an eye on it. This support would allow searching for workspaces specifically and scanning for secrets that way.

### Resources

* [https://docs.github.com/en/code-security/secret-scanning/about-secret-scanning](https://docs.github.com/en/code-security/secret-scanning/about-secret-scanning)
* [https://hackerone.com/reports/1523651](https://hackerone.com/reports/1523651)
* [https://github.com/devcoinfet/postman_research](https://github.com/devcoinfet/postman_research)
* [https://trufflesecurity.com/blog/postman-carries-lots-of-secrets](https://trufflesecurity.com/blog/postman-carries-lots-of-secrets)