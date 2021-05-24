import axios, { AxiosInstance } from 'axios';
import {
	AuthServiceLoginResponseModel,
	AuthServiceResponseModel
} from './response-model';
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
		// TODO: Check this
		const serviceAddress =
			process.env.AUTH_SERVICE_HOST || 'http://192.168.0.21:3000/';
		this.client = axios.create({ baseURL: serviceAddress });

		this.tenant = process.env.AUTH_SERVICE_TENANT_IDENTIFIER || 'playground';
	}

	async login(username: string, password: string): Promise<any> {
		const requestData = {
			email: username,
			password: password
		};

		// TODO: Add response model
		const response = await this.post<any>('user/login', requestData);
		return {
			token: response.token,
			userData: {
				message: 'logged in',
				name: 'test@test.com'
			}
		};

		// const requestParams = {
		// 	grant_type: grantType.PASSWORD,
		// 	username: username,
		// 	password: password
		// }
		// const response: AuthServiceLoginResponseModel = await this.postWithParams<any>('user/loginParams', requestParams)

		// return {
		// 	token: response.accessToken
		// };
	}

	async refresh(): Promise<any> {
		const requestParams = {
			grant_type: grantType.REFRESH_TOKEN
		};

		const additionalHeaders = {
			'Identity-RefreshToken': 'REFRESH_TOKEN'
		};

		console.log(requestParams);
		const response = await this.postWithParams<any>(
			'user/refresh',
			requestParams,
			additionalHeaders
		);

		return {
			token: response.hconfig.header.Cookie
		};
	}

	private async post<T>(action: string, requestData: any): Promise<T> {
		const requestOptions = {
			headers: {
				'X-Tenant-Identifier': this.tenant,
				'Content-Type': 'application/json'
			}
		};

		try {
			const resp = await this.client.post(action, requestData, requestOptions);
			const body = resp.data as AuthServiceResponseModel;

			if (resp.status != 200) {
				// TODO: Check this
				console.log(body)
				throw new Error(`Failed to login: ${body}`);
			}

			return body.data;
		} catch (err) {
			logger.error(err);
			throw err;
		}
	}

	private async postWithParams<T>(
		action: string,
		params: any,
		additionalHeaders?: any
	): Promise<T> {
		const requestParams = new url.URLSearchParams();
		for (const key in params) {
			requestParams.append(key, params[key]);
		}

		console.log(requestParams);

		const headers = {
			'X-Tenant-Identifier': this.tenant,
			'Content-Type': 'application/x-www-form-urlencoded',
			...additionalHeaders
		};

		const requestOptions = {
			headers: headers,
			params: requestParams.toString()
		};

		console.log(requestOptions);

		try {
			const resp = await this.client.post(action, {}, requestOptions);
			const body = resp.data as AuthServiceResponseModel;

			if (resp.status != 200) {
				// TODO: Check this
				console.log(body)
				throw new Error(`Failed to login: ${body}`);
			}

			return body.data;
		} catch (err) {
			logger.error(err);
			throw err;
		}
	}
}

module.exports = new AuthorizationService();
