import axios, { AxiosInstance } from 'axios';
import { AuthServiceResponseModel } from './response-model';
import { helper } from '../common/helper';
const url = require('url');
const logger = helper.getLogger('Authorization service');

enum grantType {
	PASSWORD = 'password',
	REFRESH_TOKEN = 'refresh_token'
}

class AuthorizationService {
	private readonly client: AxiosInstance;
	private readonly tenant: string;

	constructor() {
		const serviceAddress =
			process.env.AUTH_SERVICE_HOST || 'https://dev3-identity.sacret-life.com';
		this.client = axios.create({ baseURL: serviceAddress });

		this.tenant = process.env.AUTH_SERVICE_TENANT_IDENTIFIER || 'playground';
	}

	async login(username: string, password: string): Promise<any> {
		const requestParams = {
			grant_type: grantType.PASSWORD,
			username: username,
			password: password
		};

		const response: PostResponse = await this.postWithParams<any>(
			'identity/v1/token',
			requestParams
		);

		console.log(response);

		const cookieName =
			process.env.AUTH_SERVICE_COOKIE_NAME || 'org.apache.fincn.refreshToken';
		const refreshToken = this.getCookie(response.cookies, cookieName);

		return {
			accessToken: response.data.accessToken,
			refreshToken
		};
	}

	async refresh(username: string): Promise<any> {
		const requestParams = {
			grant_type: grantType.REFRESH_TOKEN
		};

		const additionalHeaders = {
			'Identity-RefreshToken': 'REFRESH_TOKEN',
			User: username
		};

		const response = await this.postWithParams<any>(
			'identity/v1/token',
			requestParams,
			additionalHeaders
		);

		const cookieName =
			process.env.AUTH_SERVICE_COOKIE_NAME || 'org.apache.fincn.refreshToken';
		const refreshToken = this.getCookie(response.cookies, cookieName);

		return {
			refreshToken
		};
	}

	private async postWithParams<T>(
		action: string,
		params: any,
		additionalHeaders?: any
	): Promise<PostResponse> {
		const headers = {
			'X-Tenant-Identifier': this.tenant,
			'Content-Type': 'application/x-www-form-urlencoded',
			...additionalHeaders
		};

		const requestOptions = {
			headers: headers,
			params: params,
			withCredentials: true
		};

		try {
			const resp = await this.client.post(action, {}, requestOptions);
			const body = resp.data as AuthServiceResponseModel;

			if (resp.status != 200) {
				throw new Error(`Failed to login: ${body}`);
			}

			return new PostResponse(body.data, resp.headers['set-cookie'][0]);
		} catch (err) {
			logger.error(err);
			if (err?.response?.status == 400) {
				const errData = err.response.data as AuthServiceResponseModel;
				throw new Error(`Failed to login: ${errData.message}`);
			}

			throw err;
		}
	}

	private getCookie(cookies: any, name: string): string {
		let matches = cookies.match(
			new RegExp(
				'(?:^|; )' +
					name.replace(/([\.$?*|{}\(\)\[\]\\\/\+^])/g, '\\$1') +
					'=([^;]*)'
			)
		);
		return matches ? decodeURIComponent(matches[1]) : undefined;
	}
}

class PostResponse {
	constructor(readonly data: any, readonly cookies?: any) {}
}

module.exports = new AuthorizationService();
