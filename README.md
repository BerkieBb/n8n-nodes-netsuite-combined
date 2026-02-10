# n8n-nodes-netsuite

![n8n.io - Workflow Automation](https://raw.githubusercontent.com/n8n-io/n8n/master/assets/n8n-logo.png)

n8n node for interacting with NetSuite using [SuiteTalk REST Web Services](https://docs.oracle.com/en/cloud/saas/netsuite/ns-online-help/chapter_1540391670.html).

This project has been forked to extend a few additional transaction types in NetSuite as well as patch several vulnerabilities in outdated dependencies.

The community project and its dependencies and versions is [available here on NPM](https://www.npmjs.com/package/@drowl87/n8n-nodes-netsuite).

## How to install

### Community Nodes (Recommended)

For users on n8n v0.187+, your instance owner can install this node from [Community Nodes](https://docs.n8n.io/integrations/community-nodes/installation/).

1. Go to **Settings > Community Nodes**.
2. Select **Install**.
3. Enter `@drowl87/n8n-nodes-netsuite` in **Enter npm package name**.
4. Agree to the [risks](https://docs.n8n.io/integrations/community-nodes/risks/) of using community nodes: select **I understand the risks of installing unverified code from a public source**.
5. Select **Install**.

After installing the node, you can use it like any other node. n8n displays the node in search results in the **Nodes** panel.

### Manual installation

To get started install the package in your n8n root directory:

`npm install @drowl87/n8n-nodes-netsuite`

For Docker-based deployments, add the following line before the font installation command in your [n8n Dockerfile](https://github.com/n8n-io/n8n/blob/master/docker/images/n8n/Dockerfile):

`RUN cd /usr/local/lib/node_modules/n8n && npm install @drowl87/n8n-nodes-netsuite`

## Configuration

### NetSuite
1. Go to **Setup > Company > Enable Features**, navigate to the **SuiteCloud** tab. Under **Manage Authentication**, make sure that `Token-Based Authentication` is enabled.
2. Go to **Setup > Integration > Manage Integrations > New** and name it something like `n8n Integration` and add a description. Leave `Token-Based Authentication` enabled, but uncheck `TBA: Authorization Flow` and any of the checkboxes under the `OAuth 2.0` heading. Save the `Consumer Key/Secret` for configuration with n8n.
3. Go to **Setup > Users/Roles > Manage Roles > New** and make a custom role in NetSuite such as `REST API Integration - n8n`. **NOTE**: You may need to play around with permissions and add more if you are running into access errors.
	- Under the **Authentication** header/dropdown, set it as a `Web services only` role
	- Assign whatever **Transactions** or **Lists** permisions that align with your use case
	- On **Setup**, make sure you assign at least `Log in using Access Tokens`, `User Access Tokens`, and `REST Web Services`
4. Go to **Lists > Employees > Employees** and select a user. On the `Access` tab, assign the newly-created role.
5. Go to **Setup > Users/Roles > Access Tokens > New**. Select the application name and user and role from above. Save the `Token Key/Secret` for configuration with n8n.

### n8n
1. Add NetSuite node to a workflow
2. For credentials, assuming your regular NetSuite URL is `https://1234567.app.netsuite.com`, click `+Create new credential`
 	- **Hostname**: Your hostname for this field would be `1234567.suitetalk.api.netsuite.com`
 	- **Account ID**: This field's value would be `1234567`
 	- **Consumer Key/Secret**: These fields come from the [NetSuite integration](https://docs.oracle.com/en/cloud/saas/netsuite/ns-online-help/chapter_1540391670.html) located at `https://1234567.app.netsuite.com/app/common/integration/integrapplist.nl?whence=`
 	- **Token Key/Secret**: These fields come from the access token that you configured at `https://1234567.app.netsuite.com/app/setup/accesstokens.nl?whence=`

## Contributing

I'm fairly new to n8n so please feel free to add onto this and submit pull requests. Many thanks to the original work by [drudge](https://github.com/drudge/n8n-nodes-netsuite) and additions by [ianpogi5](https://github.com/ianpogi5/n8n-nodes-netsuite).

## License

MIT License

Copyright (c) 2022 Nicholas Penree <nick@penree.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
