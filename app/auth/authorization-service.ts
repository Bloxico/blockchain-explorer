import axios, { AxiosInstance } from 'axios';
import { AuthServiceResponseModel } from './response-model';
import { helper } from '../common/helper';
const logger = helper.getLogger('Authorization service');
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

		const response = await this.postWithParams<any>(
			'identity/v1/oauth/token',
			requestData
		);

		const cookieName =
			process.env.AUTH_SERVICE_COOKIE_NAME || 'org.apache.fincn.refreshToken';
		const refreshToken = this.getCookie(response.cookies, cookieName);

		return {
			refreshToken
		};
	}

	readPublicKey(): string {
		const keyExponent = process.env.PUB_KEY_EXPONENT || 65537;
		const keyModulus =
			process.env.PUB_KEY_MODULUS ||
			'28056766528298092316603009461519456197217107392685421861112741554301407376444658302710098898935558361014681847152876425907854935416879746836636085958109743349355620643507838411475504252189635187536054983744167096114328970578943576910461505826445785538030876555377595709373293556895592793635583438567865363778910874085393648922546565066510055797281726517560944397049726111800465605625116338897663452989642466580175271783317048698601742414016722624603080404503008641058650800954396543579163393231408590636089565521022596510913814783746448189779508116600448669908959654209537829895139231941952607561568921429984821076921';

		const pubKey = new NodeRSA();
		pubKey.importKey(
			{
				n: Buffer.from(keyModulus, 'hex'),
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
