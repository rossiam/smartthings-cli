import type {
	SmartAppListOptions,
	SmartAppResponse,
	PagedSmartApp,
	SmartThingsClient,
} from '@smartthings/core-sdk'


export const verboseSmartApps = async (
		client: SmartThingsClient,
		listOptions: SmartAppListOptions,
): Promise<SmartAppResponse[]> => {
	const apps = await client.smartapps.list(listOptions)
	return Promise.all(apps.map(app => client.smartapps.get(app.appId)))
}

export const shortARNorURL = (app: PagedSmartApp & Partial<SmartAppResponse>): string => {
	const uri = (app.webhookSmartApp
		? app.webhookSmartApp.targetUrl
		: (app.lambdaSmartApp
			? (app.lambdaSmartApp.functions?.length ? app.lambdaSmartApp.functions[0] : '')
			: (app.apiOnly?.subscription?.targetUrl))) ?? ''

	return uri.length < 96 ? uri : uri.slice(0, 95) + '...'
}
