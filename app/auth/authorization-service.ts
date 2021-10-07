import axios, { AxiosInstance } from 'axios';
import { AuthServiceResponseModel } from './response-model';
import { helper } from '../common/helper';
const logger = helper.getLogger('Authorization service');
const bigint = require('big-integer');
import NodeRSA, * as rsa from 'node-rsa';

enum grantType {
	PASSWORD = 'password',
	REFRESH_TOKEN = 'refresh_token'
}

class AuthorizationService {
	private readonly client: AxiosInstance;
	private readonly clientId: string;
	private readonly clientSecret: string;
	private readonly clientScope: string;

	constructor() {
		const serviceAddress =
			process.env.AUTH_SERVICE_HOST || 'https://dev3-identity.sacret-life.com';
		this.client = axios.create({ baseURL: serviceAddress });

		this.clientId = process.env.CLIENT_ID || 'c2';
		this.clientSecret = process.env.CLIENT_SECRET || 's';
		this.clientScope = process.env.CLIENT_SCOPE || 'any';
	}

	async login(username: string, password: string): Promise<any> {
		const requestData = {
			grant_type: grantType.PASSWORD,
			username: username,
			password: password,
			client_id: this.clientId,
			client_secret: this.clientSecret,
			scope: this.clientScope
		};

		const response: PostResponse = await this.postWithParams<any>(
			'identity/v1/oauth/token',
			requestData
		);
		const responseData: AuthServiceResponseModel = response.data;

		return {
			accessToken: responseData.access_token,
			refreshToken: responseData.refresh_token
		};
	}

	async refresh(oldRefreshToken: string): Promise<any> {
		const requestData = {
			grant_type: grantType.REFRESH_TOKEN,
			refresh_token: oldRefreshToken,
			client_id: this.clientId,
			client_secret: this.clientSecret
		};

		const response: PostResponse = await this.postWithParams<any>(
			'identity/v1/oauth/token',
			requestData
		);
		const responseData: AuthServiceResponseModel = response.data;

		return {
			accessToken: responseData.access_token,
			refreshToken: responseData.refresh_token
		};
	}

	readPublicKey(): string {
		const keyExponent = process.env.PUB_KEY_EXPONENT || '65537';
		const keyModulus =
			process.env.PUB_KEY_MODULUS ||
			'22943090542451527479433256172074502302629256446444698014214325506385355572768438609313649502884005879150311850765056722211290446847815022061400860115549942785148595519337998472320335714089858229186882436768310178416535204829808484055673399833828283347815195140052612349989420655199923132176988918170987082661868487236226975876280851868764194834417734441474471334774835063750551817237035041514377269459509685626373965318080278312253717943650835301339321013329553178131699698416047734299287582996874005134205801659441167889038254614218753374445611251640872947836627649381332325181853304995356955673785660108815536307577';

		const keyModulusHex = bigint(keyModulus).toString(16);
		const pubKey = new NodeRSA();
		pubKey.importKey(
			{
				n: Buffer.from(keyModulusHex, 'hex'),
				e: Number(keyExponent)
			},
			'components-public'
		);
		return pubKey.exportKey('public');
	}

	private async post<T>(
		action: string,
		requestData: any,
		additionalHeaders?: any
	): Promise<PostResponse> {
		const headers = {
			'Content-Type': 'application/json',
			...additionalHeaders
		};

		const requestOptions = {
			headers: headers,
			withCredentials: true
		};

		try {
			const resp = await this.client.post(action, requestData, requestOptions);
			const body = resp.data as AuthServiceResponseModel;

			if (resp.status != 200) {
				throw new Error(`Failed to login: ${body}`);
			}

			return new PostResponse(body, resp.headers['set-cookie'][0]);
		} catch (err) {
			logger.error(err);
			throw err;
		}
	}

	private async postWithParams<T>(
		action: string,
		params: any,
		additionalHeaders?: any
	): Promise<PostResponse> {
		const headers = {
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

			return new PostResponse(body);
		} catch (err) {
			logger.error(err);
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
