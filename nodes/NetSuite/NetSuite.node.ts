import { debuglog } from 'util';
import * as crypto from 'crypto';

import {
	IDataObject,
	IExecuteFunctions,
	IHttpRequestMethods,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
	JsonObject,
	NodeApiError,
} from 'n8n-workflow';

import {
	INetSuiteCredentials,
	INetSuiteOperationOptions,
	INetSuitePagedBody,
	INetSuiteRequestOptions,
	INetSuiteResponse,
	NetSuiteRequestType,
} from './NetSuite.node.types';

import {
	nodeDescription,
} from './NetSuite.node.options';

import pLimit from '@common.js/p-limit';

const debug = debuglog('n8n-nodes-netsuite');

// OAuth 1.0a implementation
const createOAuth = (credentials: INetSuiteCredentials) => {
	const nonceLength = 20;
	const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';

	const generateNonce = () => {
		let result = '';
		for (let i = 0; i < nonceLength; i++) {
			result += chars.charAt(Math.floor(Math.random() * chars.length));
		}

		return result;
	};

	const percentEncode = (str: string) => {
		return encodeURIComponent(str)
			.replace(/!/g, '%21')
			.replace(/\*/g, '%2A')
			.replace(/'/g, '%27')
			.replace(/\(/g, '%28')
			.replace(/\)/g, '%29');
	};

	const getBaseString  = (method: string, url: string, params: Record<string, string>) => {
		const sortedParams = Object.keys(params)
			.sort()
			.map(key => `${percentEncode(key)}=${percentEncode(params[key])}`)
			.join('&')

		const urlObj = new URL(url);
		const baseUrl = `${urlObj.protocol}//${urlObj.host}${urlObj.pathname}`;
		return `${method.toUpperCase()}&${percentEncode(baseUrl)}&${percentEncode(sortedParams)}`;
	};

	const getSigningKey = () => {
		return `${percentEncode(credentials.consumerSecret)}&${percentEncode(credentials.tokenSecret)}`;
	};

	const sign = (baseString: string) => {
		return crypto
			.createHmac('sha256', getSigningKey())
			.update(baseString)
			.digest('base64');
	};

	return {
		getAuthHeader: (method: string, url: string) => {
			const timestamp = Math.floor(Date.now() / 1000).toString();
			const nonce = generateNonce();
			const oauthParams: Record<string, string> = {
				oauth_consumer_key: credentials.consumerKey,
				oauth_nonce: nonce,
				oauth_signature_method: 'HMAC-SHA256',
				oauth_timestamp: timestamp,
				oauth_token: credentials.tokenKey,
				oauth_version: '1.0'
			};

			const baseString = getBaseString(method, url, oauthParams);
			const signature = sign(baseString);
			oauthParams.oauth_signature = signature;

			const authHeader = 'OAuth realm="' + credentials.accountId + '",' +
				Object.keys(oauthParams)
					.sort()
					.map(key => `${percentEncode(key)}="${percentEncode(oauthParams[key])}"`)
					.join(',');

			return { Authorization: authHeader };
		}
	}
};

// Custom makeRequest using n8n's httpRequest helper
const makeNetSuiteRequest = async (
	fns: IExecuteFunctions,
	credentials: INetSuiteCredentials,
	requestOptions: INetSuiteRequestOptions,
	customHeaders: Record<string, string> = {}
) => {
	const { method, path, query, nextUrl, requestType } = requestOptions;

	// Build URL
	const url: string = nextUrl || `https://${credentials.hostname}/${path}`;

	// Get OAuth headers
	const oauth = createOAuth(credentials);
	const oauthHeaders = oauth.getAuthHeader(method, url);

	// Merge headers
	const headers: Record<string, string> = {
		...oauthHeaders,
		'Content-Type': 'application/json; charset=utf-8',
		'prefer': 'transient',
		...customHeaders
	};

	// Build body
	let body = undefined;
	if (query && !['GET', 'HEAD', 'OPTIONS'].includes(method)) {
		if (requestType === NetSuiteRequestType.SuiteQL) {
			body = { q: query };
		} else {
			body = typeof query === 'string' ? JSON.parse(query) : query;
		}
	}

	debug('makeNetSuiteRequest URL:', url);
	debug('makeNetSuiteRequest method:', method);
	debug('makeNetSuiteRequest headers:', headers);

	const response = await fns.helpers.httpRequest({
		method: method as IHttpRequestMethods,
		url,
		headers,
		body,
		returnFullResponse: true,
		ignoreHttpStatusErrors: true,
		json: true
	});

	return {
		statusCode: response.statusCode,
		statusText: response.statusCode >= 200 && response.statusCode < 300 ? 'OK' : 'Error',
		body: response.body,
		headers: response.headers,
		request: { options: { method } }
	};
};

const handleNetsuiteResponse = (fns: IExecuteFunctions, response: INetSuiteResponse) => {
	debug(`Netsuite response:`, response.statusCode, response.body);
	let body: JsonObject = {};
	const responseBody = response.body || {};
	const {
		title: webTitle = undefined,
		'o:errorCode': webCode,
		'o:errorDetails': webDetails,
		message: restletMessage = undefined,
	} = responseBody;

	if (!(response.statusCode && response.statusCode >= 200 && response.statusCode < 400)) {
		let message = webTitle || restletMessage || webCode || response.statusText;
		if (webDetails && webDetails.length > 0) {
			message = webDetails[0].detail || message;
		}

		if (fns.continueOnFail() !== true) {
			const error = new NodeApiError(fns.getNode(), responseBody);
			error.message = message;
			throw error;
		} else {
			body = {
				error: message,
			};
		}
	} else {
		body = responseBody;

		// Ensure response.request.options is not null and has a 'method' property.
		const requestOptions = response.request.options as { method?: string } | null;
		if (requestOptions?.method && [ 'POST', 'PATCH', 'DELETE' ].includes(requestOptions.method)) {
			body = typeof body === 'object' ? responseBody : {};
			if (response.headers['x-netsuite-propertyvalidation']) {
				body.propertyValidation = response.headers['x-netsuite-propertyvalidation'].split(',');
			}

			if (response.headers['x-n-operationid']) {
				body.operationId = response.headers['x-n-operationid'];
			}

			if (response.headers['x-netsuite-jobid']) {
				body.jobId = response.headers['x-netsuite-jobid'];
			}

			if (response.headers['location']) {
				body.links = [
					{
						rel: 'self',
						href: response.headers['location'],
					},
				];
				// Guard against undefined: split and check the result.
				const locParts = response.headers['location'].split('/');
				const locId = locParts.pop() ?? null;
				if (locId !== null) {
					body.id = locId;
				}
			}

			body.success = response.statusCode === 204;
		}
	}

	return { json: body };
};

export class NetSuite implements INodeType {
	description: INodeTypeDescription = nodeDescription;

	static getRecordType({ fns, itemIndex }: INetSuiteOperationOptions): string {
		let recordType = fns.getNodeParameter('recordType', itemIndex) as string;
		if (recordType === 'custom') {
			recordType = fns.getNodeParameter('customRecordTypeScriptId', itemIndex) as string;
		}
		return recordType;
	}

	static async listRecords(options: INetSuiteOperationOptions): Promise<INodeExecutionData[]> {
		const { fns, credentials, itemIndex } = options;
		const nodeContext = fns.getContext('node');
		const apiVersion = fns.getNodeParameter('version', itemIndex) as string;
		const recordType = NetSuite.getRecordType(options);
		const returnAll = fns.getNodeParameter('returnAll', itemIndex) as boolean;
		const query = fns.getNodeParameter('query', itemIndex) as string;
		let limit = 100;
		let offset = 0;
		let hasMore = true;
		const method = 'GET';
		let nextUrl;
		const requestType = NetSuiteRequestType.Record;
		const params = new URLSearchParams();
		const returnData: INodeExecutionData[] = [];
		let prefix = query ? `?${query}` : '';
		if (returnAll !== true) {
			prefix = query ? `${prefix}&` : '?';
			limit = fns.getNodeParameter('limit', itemIndex) as number || limit;
			offset = fns.getNodeParameter('offset', itemIndex) as number || offset;
			params.set('limit', String(limit));
			params.set('offset', String(offset));
			prefix += params.toString();
		}
		const requestData: INetSuiteRequestOptions = {
			method,
			requestType,
			path: `services/rest/record/${apiVersion}/${recordType}${prefix}`,
		};
		nodeContext.hasMore = hasMore;
		nodeContext.count = limit;
		nodeContext.offset = offset;

		while ((returnAll || returnData.length < limit) && hasMore === true) {
			const response = await makeNetSuiteRequest(fns, credentials, requestData);
			const body: JsonObject = handleNetsuiteResponse(fns, response);
			const { hasMore: doContinue, items, links, offset: respOffset, count, totalResults } = (body.json as INetSuitePagedBody);
			if (doContinue) {
				nextUrl = (links.find((link) => link.rel === 'next') || {}).href;
				requestData.nextUrl = nextUrl;
			}
			if (Array.isArray(items)) {
				for (const json of items) {
					if (returnAll || returnData.length < limit) {
						returnData.push({ json });
					}
				}
			}
			hasMore = doContinue && (returnAll || returnData.length < limit);
			nodeContext.hasMore = doContinue;
			nodeContext.count = count;
			nodeContext.offset = respOffset;
			nodeContext.totalResults = totalResults;
			if (requestData.nextUrl) {
				nodeContext.nextUrl = requestData.nextUrl;
			}
		}
		return returnData;
	}

	static async runSuiteQL(options: INetSuiteOperationOptions): Promise<INodeExecutionData[]> {
		const { fns, credentials, itemIndex } = options;
		const nodeContext = fns.getContext('node');
		const apiVersion = fns.getNodeParameter('version', itemIndex) as string;
		const returnAll = fns.getNodeParameter('returnAll', itemIndex) as boolean;
		// For SuiteQL the query is provided as a string.
		const query = fns.getNodeParameter('query', itemIndex) as string;
		let limit = 1000;
		let offset = 0;
		let hasMore = true;
		const method = 'POST';
		let nextUrl;
		const requestType = NetSuiteRequestType.SuiteQL;
		const params = new URLSearchParams();
		const returnData: INodeExecutionData[] = [];
		let prefix = '?';
		if (returnAll !== true) {
			limit = fns.getNodeParameter('limit', itemIndex) as number || limit;
			offset = fns.getNodeParameter('offset', itemIndex) as number || offset;
			params.set('offset', String(offset));
		}
		params.set('limit', String(limit));
		prefix += params.toString();
		const requestData: INetSuiteRequestOptions = {
				method,
				requestType,
				query,
				path: `services/rest/query/${apiVersion}/suiteql${prefix}`
		};

		nodeContext.hasMore = hasMore;
		nodeContext.count = limit;
		nodeContext.offset = offset;
		debug('requestData', requestData);
		while ((returnAll || returnData.length < limit) && hasMore === true) {
			const response = await makeNetSuiteRequest(fns, credentials, requestData);
			const body: JsonObject = handleNetsuiteResponse(fns, response);
			const { hasMore: doContinue, items, links, count, totalResults, offset: respOffset } = (body.json as INetSuitePagedBody);
			if (doContinue) {
				nextUrl = (links.find((link) => link.rel === 'next') || {}).href;
				requestData.nextUrl = nextUrl;
			}
			if (Array.isArray(items)) {
				for (const json of items) {
					if (returnAll || returnData.length < limit) {
						returnData.push({ json });
					}
				}
			}
			hasMore = doContinue && (returnAll || returnData.length < limit);
			nodeContext.hasMore = doContinue;
			nodeContext.count = count;
			nodeContext.offset = respOffset;
			nodeContext.totalResults = totalResults;
			if (requestData.nextUrl) {
				nodeContext.nextUrl = requestData.nextUrl;
			}
		}
		return returnData;
	}

	static async getRecord(options: INetSuiteOperationOptions): Promise<INodeExecutionData> {
		const { item, fns, credentials, itemIndex } = options;
		const params = new URLSearchParams();
		const expandSubResources = fns.getNodeParameter('expandSubResources', itemIndex) as boolean;
		const simpleEnumFormat = fns.getNodeParameter('simpleEnumFormat', itemIndex) as boolean;
		const apiVersion = fns.getNodeParameter('version', itemIndex) as string;
		const recordType = NetSuite.getRecordType(options);
		const internalId = fns.getNodeParameter('internalId', itemIndex) as string;
		if (expandSubResources) {
			params.append('expandSubResources', 'true');
		}
		if (simpleEnumFormat) {
			params.append('simpleEnumFormat', 'true');
		}
		const q = params.toString();
		const requestData: INetSuiteRequestOptions = {
			method: 'GET',
			requestType: NetSuiteRequestType.Record,
			path: `services/rest/record/${apiVersion}/${recordType}/${internalId}${q ? `?${q}` : ''}`,
		};
		const response = await makeNetSuiteRequest(fns, credentials, requestData);
		if (item) response.body.orderNo = item.json.orderNo;
		return handleNetsuiteResponse(fns, response);
	}

	static async removeRecord(options: INetSuiteOperationOptions): Promise<INodeExecutionData> {
		const { fns, credentials, itemIndex } = options;
		const apiVersion = fns.getNodeParameter('version', itemIndex) as string;
		const recordType = NetSuite.getRecordType(options);
		const internalId = fns.getNodeParameter('internalId', itemIndex) as string;
		const requestData: INetSuiteRequestOptions = {
			method: 'DELETE',
			requestType: NetSuiteRequestType.Record,
			path: `services/rest/record/${apiVersion}/${recordType}/${internalId}`,
		};
		const response = await makeNetSuiteRequest(fns, credentials, requestData);
		return handleNetsuiteResponse(fns, response);
	}

	static async insertRecord(options: INetSuiteOperationOptions): Promise<INodeExecutionData> {
		const { fns, credentials, itemIndex, item } = options;
		const apiVersion = fns.getNodeParameter('version', itemIndex) as string;
		const recordType = NetSuite.getRecordType(options);
		// Expecting an object from the incoming item.
		const query = item ? item.json : undefined;
		const requestData: INetSuiteRequestOptions = {
			method: 'POST',
			requestType: NetSuiteRequestType.Record,
			path: `services/rest/record/${apiVersion}/${recordType}`,
		};
		if (query) {
			// Cast to the expected type.
			requestData.query = query as Record<string, string | number | boolean>;
		}
		const response = await makeNetSuiteRequest(fns, credentials, requestData);
		return handleNetsuiteResponse(fns, response);
	}

	static async updateRecord(options: INetSuiteOperationOptions): Promise<INodeExecutionData> {
		const { fns, credentials, itemIndex, item } = options;
		const apiVersion = fns.getNodeParameter('version', itemIndex) as string;
		const recordType = NetSuite.getRecordType(options);
		const internalId = fns.getNodeParameter('internalId', itemIndex) as string;
		// Expecting an object from the incoming item.
		const query = item ? item.json : undefined;
		const requestData: INetSuiteRequestOptions = {
			method: 'PATCH',
			requestType: NetSuiteRequestType.Record,
			path: `services/rest/record/${apiVersion}/${recordType}/${internalId}`,
		};
		if (query) {
			// Cast to the expected type.
			requestData.query = query as Record<string, string | number | boolean>;
		}
		const response = await makeNetSuiteRequest(fns, credentials, requestData);
		return handleNetsuiteResponse(fns, response);
	}

	static async rawRequest(options: INetSuiteOperationOptions): Promise<INodeExecutionData> {
		const { fns, credentials, itemIndex, item } = options;
		const nodeContext = fns.getContext('node');
		let path = fns.getNodeParameter('path', itemIndex) as string;
		const method = fns.getNodeParameter('method', itemIndex) as string;
		const body = fns.getNodeParameter('body', itemIndex) as string;
		const requestType = fns.getNodeParameter('requestType', itemIndex) as NetSuiteRequestType;
		// The query can come as a string (body) or an object (from the item).
		const query = body || (item ? item.json : undefined);
		const nodeOptions = fns.getNodeParameter('options', 0) as IDataObject;

		// Get custom headers
		const customHeadersData = fns.getNodeParameter('customHeaders', itemIndex, {}) as IDataObject;
		const customHeaders: Record<string, string> = {};
		if (customHeadersData.header && Array.isArray(customHeadersData.header)) {
			for (const headerItem of customHeadersData.header) {
				const headerObj = headerItem as { name: string; value: string };
				if (headerObj.name && headerObj.value) {
					customHeaders[headerObj.name] = headerObj.value;
				}
			}
		}

		if (path && (path.startsWith('https://') || path.startsWith('http://'))) {
			const url = new URL(path);
			path = `${url.pathname.replace(/^\//, '')}${url.search || ''}`;
		}

		const requestData: INetSuiteRequestOptions = {
			method,
			requestType,
			path,
		};

		if (query && !['GET', 'HEAD', 'OPTIONS'].includes(method)) {
			try {
				const parsedQuery = typeof query === 'string' ? JSON.parse(query) : query;
				if (typeof parsedQuery === 'string') {
					requestData.query = parsedQuery;
				} else {
					// Cast the parsed object to the expected type.
					requestData.query = parsedQuery as Record<string, string | number | boolean>;
				}
			} catch {
				requestData.query = query as string | Record<string, string | number | boolean> | undefined;
			}
		}

		// Manually strip "query" wrapper if it exists
		if ((requestData.query as Record<string, unknown>)?.query) {
			requestData.query = ((requestData.query as Record<string, unknown>).query) as Record<string, string | number | boolean>;
		}

		debug('Final cleaned requestData:', JSON.stringify(requestData, null, 2));
		const response = await makeNetSuiteRequest(fns, credentials, requestData);
		const respBody = response.body;

		if (respBody) {
			nodeContext.hasMore = respBody.hasMore;
			nodeContext.count = respBody.count;
			nodeContext.offset = respBody.offset;
			nodeContext.totalResults = respBody.totalResults;
		}

		if (nodeOptions.fullResponse) {
			return {
				json: {
					statusCode: response.statusCode,
					headers: response.headers,
					body: respBody,
				}
			};
		} else {
			return { json: respBody as JsonObject };
		}
	}

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const credentials: INetSuiteCredentials = (await this.getCredentials('netsuite')) as INetSuiteCredentials;
		const operation = this.getNodeParameter('operation', 0) as string;
		const items: INodeExecutionData[] = this.getInputData();
		const returnData: INodeExecutionData[] = [];
		const promises = [];
		const options = this.getNodeParameter('options', 0) as IDataObject;
		const concurrency = (options.concurrency as number) || 1;
		const limit = pLimit(concurrency);

		for (let itemIndex = 0; itemIndex < items.length; itemIndex++) {
			const item: INodeExecutionData = items[itemIndex];
			let data: INodeExecutionData | INodeExecutionData[];

			promises.push(limit(async () => {
				debug(`Processing ${operation} for ${itemIndex + 1} of ${items.length}`);
				if (operation === 'getRecord') {
					data = await NetSuite.getRecord({ item, fns: this, credentials, itemIndex });
				} else if (operation === 'listRecords') {
					data = await NetSuite.listRecords({ item, fns: this, credentials, itemIndex });
				} else if (operation === 'removeRecord') {
					data = await NetSuite.removeRecord({ item, fns: this, credentials, itemIndex });
				} else if (operation === 'insertRecord') {
					data = await NetSuite.insertRecord({ item, fns: this, credentials, itemIndex });
				} else if (operation === 'updateRecord') {
					data = await NetSuite.updateRecord({ item, fns: this, credentials, itemIndex });
				} else if (operation === 'rawRequest') {
					data = await NetSuite.rawRequest({ item, fns: this, credentials, itemIndex });
				} else if (operation === 'runSuiteQL') {
					data = await NetSuite.runSuiteQL({ item, fns: this, credentials, itemIndex });
				} else {
					const error = `The operation "${operation}" is not supported!`;
					if (this.continueOnFail() !== true) {
						throw new Error(error);
					} else {
						data = { json: { error } };
					}
				}
				return data;
			}));
		}

		const results = await Promise.all(promises);
		for await (const result of results) {
			if (result) {
				if (Array.isArray(result)) {
					returnData.push(...result);
				} else {
					returnData.push(result);
				}
			}
		}

		return this.prepareOutputData(returnData);
	}
}
