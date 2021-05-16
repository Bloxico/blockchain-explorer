import axios, { AxiosInstance } from 'axios';
import { AuthServiceResponseModel } from './response-model';
import { helper } from '../common/helper';
const logger = helper.getLogger('Authorization service');

class AuthorizationService {
	private readonly client: AxiosInstance;
	private readonly apiKey: string;

	constructor() {
		// TODO: Check this
		const serviceAddress =
			process.env.AUTH_SERVICE_HOST || 'http://192.168.0.37:3000/';
		this.client = axios.create({ baseURL: serviceAddress });

		this.apiKey = process.env.AUTH_SERVICE_API_KEY || 'aaa';
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
	}

	async check(token: string): Promise<any> {
		const requestData = {
			token: token
		};

		// TODO: Add response model
		const response = await this.post<any>('user/check', requestData);

		return {
			user: 'test@test.com',
			network: 'slaff-test-network'
		};
	}

	private async post<T>(action: string, requestData: any): Promise<T> {
		const requestOptions = {
			headers: {
				'api-key': this.apiKey
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
}

module.exports = new AuthorizationService();
