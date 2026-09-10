import { jest } from '@jest/globals'

import {
	type SmartAppResponse,
	type SmartAppsEndpoint,
	type PagedSmartApp,
	type SmartThingsClient,
} from '@smartthings/core-sdk'


const {
	shortARNorURL,
	verboseSmartApps,
} = await import('../../../../lib/command/util/smartapps-util.js')


describe('verboseSmartApps', () => {
	const listMock = jest.fn<typeof SmartAppsEndpoint.prototype.list>()
	const getMock = jest.fn<typeof SmartAppsEndpoint.prototype.get>()
	const smartapps = { list: listMock, get: getMock } as unknown as SmartAppsEndpoint
	const client = { smartapps } as SmartThingsClient

	it('passes options to list', async () => {
		listMock.mockResolvedValueOnce([])
		const options = { appType: 'API_ONLY' } as const

		expect(await verboseSmartApps(client, options))

		expect(listMock).toHaveBeenCalledExactlyOnceWith(options)
		expect(getMock).toHaveBeenCalledTimes(0)
	})

	it('uses get for every item in list', async () => {
		const pagedApp1 = { appId: 'paged-app-1-id' } as PagedSmartApp
		const pagedApp2 = { appId: 'paged-app-2-id' } as PagedSmartApp
		const verboseApp1 = { appId: 'verbose-app-1-id' } as SmartAppResponse
		const verboseApp2 = { appId: 'verbose-app-2-id' } as SmartAppResponse

		listMock.mockResolvedValueOnce([pagedApp1, pagedApp2])
		getMock.mockResolvedValueOnce(verboseApp1)
		getMock.mockResolvedValueOnce(verboseApp2)

		expect(await verboseSmartApps(client, {}))

		expect(listMock).toHaveBeenCalledExactlyOnceWith({})
		expect(getMock).toHaveBeenCalledTimes(2)
		expect(getMock).toHaveBeenCalledWith('paged-app-1-id')
		expect(getMock).toHaveBeenCalledWith('paged-app-2-id')
	})
})

describe('shortARNorURL', () => {
	it('uses webhookSmartApp targetUrl', () => {
		const targetUrl = 'webhook target URL'
		expect(shortARNorURL({ webhookSmartApp: { targetUrl } } as unknown as PagedSmartApp)).toBe(targetUrl)
	})

	it('uses first lambdaSmartApp function', () => {
		expect(shortARNorURL({ lambdaSmartApp: { functions: ['function 1'] } } as unknown as PagedSmartApp))
			.toBe('function 1')
	})

	it('uses empty string for lambdaSmartApp empty function list', () => {
		expect(shortARNorURL({ lambdaSmartApp: {} } as unknown as PagedSmartApp)).toBe('')
		expect(shortARNorURL({ lambdaSmartApp: { functions: [] } } as unknown as PagedSmartApp)).toBe('')
	})

	it('uses apiOnly subscription targetUrl', () => {
		const targetUrl = 'apiOnly subscription URL'
		expect(shortARNorURL({ apiOnly: { subscription: { targetUrl } } } as unknown as PagedSmartApp)).toBe(targetUrl)
		expect(shortARNorURL({ apiOnly: {} } as unknown as PagedSmartApp)).toBe('')
		expect(shortARNorURL({ apiOnly: { subscription: {} } } as unknown as PagedSmartApp)).toBe('')
	})

	it('falls back on an empty string', () => {
		expect(shortARNorURL({} as unknown as PagedSmartApp)).toBe('')
	})

	it.each([
		'short URL',
		'12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345',
	])('includes full URL for short URLs', (targetUrl) => {
		expect(shortARNorURL({ webhookSmartApp: { targetUrl } } as unknown as PagedSmartApp)).toBe(targetUrl)
	})

	it('trims long URLs', () => {
		const targetUrl = '123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456'
		const trimmed = '12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345...'
		expect(shortARNorURL({ webhookSmartApp: { targetUrl } } as unknown as PagedSmartApp)).toBe(trimmed)
	})
})
