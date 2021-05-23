import axios, { AxiosInstance } from 'axios';
import { AuthServiceResponseModel } from './response-model';
import { helper } from '../common/helper';
const logger = helper.getLogger('Authorization service');

class AuthorizationService {
	private readonly client: AxiosInstance;
	private readonly tenant: string;

	constructor() {
		// TODO: Check this
		const serviceAddress =
			process.env.AUTH_SERVICE_HOST || 'http://192.168.100.102:3000/';
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

		// const requestParams = {
		// 	grant_type: "password",
		// 	username: username,
		// 	password: password
		// }
		// const response = await this.postWithParams<any>('user/login', requestParams)

		return {
			token: response.token,
			userData: {
				message: 'logged in',
				name: 'test@test.com'
			}
		};
	}

	// TODO: Refresh

	private async post<T>(
		action: string,
		requestData: any,
		additionalHeaders?: string
	): Promise<T> {
		const requestOptions = {
			headers: {
				'X-Tenant-Identifier': this.tenant,
				'Content-Type': 'application/json'
			}
		};

		try {
			const resp = await this.client.post(action, requestData, requestOptions);
			const body = resp.data as AuthServiceResponseModel;
			return body.data;
		} catch (err) {
			// TODO: Handle Error Here
			logger.error(err);
		}
	}

	private async postWithParams<T>(
		action: string,
		params: any,
		additionalHeaders?: string
	): Promise<T> {
		const requestOptions = {
			headers: {
				'X-Tenant-Identifier': this.tenant,
				'Content-Type': 'application/json'
			},
			params: params
		};

		try {
			const resp = await this.client.post(action, null, requestOptions);
			const body = resp.data as AuthServiceResponseModel;
			return body.data;
		} catch (err) {
			// TODO: Handle Error Here
			logger.error(err);
		}
	}
}

module.exports = new AuthorizationService();
