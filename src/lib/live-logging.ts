import https from 'node:https'
import net from 'node:net'
import { PeerCertificate, TLSSocket } from 'node:tls'
import { ClientRequest } from 'node:http'
import { inspect } from 'node:util'
import os from 'node:os'

import axios, { AxiosError, AxiosResponse, Method } from 'axios'
import log4js from 'log4js'

import { Authenticator } from '@smartthings/core-sdk'

import { bgBlue, bgCyan, bgGray, bgGreen, bgRed, bgYellow, black } from './colors.js'
import { fatalError } from './util.js'


export const logLevels = {
	trace: { value: 100, color: bgGreen },
	debug: { value: 200, color: bgCyan },
	info: { value: 300, color: bgBlue },
	warn: { value: 400, color: bgYellow },
	error: { value: 500, color: bgRed },
	fatal: { value: 600, color: bgRed },
	print: { value: 1000, color: bgGray },
} as const
export type LogLevel = keyof typeof logLevels

export type LiveLogMessage = {
	/*
	 * The ISO formatted Local timestamp
	 */
	timestamp: string

	/**
	 * A UUID for this driver
	 */
	driver_id: string

	/**
	 * The human readable name of this driver
	 */
	driver_name: string

	/**
	 * The level this message is logged at
	 */
	log_level: number

	/**
	 * The content of this message
	 */
	message: string
}

export const isLiveLogMessage = (event: unknown): event is LiveLogMessage => {
	const liveLogEvent = event as LiveLogMessage
	return typeof liveLogEvent.timestamp === 'string' &&
		typeof liveLogEvent.driver_id === 'string' &&
		typeof liveLogEvent.driver_name === 'string' &&
		typeof liveLogEvent.log_level === 'number' &&
		typeof liveLogEvent.message === 'string'
}

// TODO: this isn't used except in a test, can we remove?
export enum DriverInfoStatus {
	NoArchive = 'no archive',
	Downloading = 'downloading',
	Installed = 'installed',
	Failure = 'failure',
	Unknown = 'unknown',
}

export type DriverInfo = {
	/**
	 * A UUID for this driver
	 * */
	driver_id: string

	/**
	 * The human readable name of this driver
	 * */
	driver_name: string

	/**
	 * If installed, the sha256 hash of the archive that was downloaded
	 * */
	archive_hash?: string | null

	/**
	 * The current status of this driver
	 * */
	status: string
}

const levelInfoByLogLevelNumber = Object.fromEntries(
	Object.entries(logLevels).map(([name, info]) => [info.value, { name, info }]),
)
// Get the log level named with coloring decorations for terminal output.
const formattedLevelName = (level: number): string => {
	const levelInfo = levelInfoByLogLevelNumber[level]
	const colorString = levelInfo.info.color(levelInfo.name.toUpperCase())

	// black text seems to provide better contrast in most terminals
	return black(colorString)
}

export const liveLogMessageFormatter = (event: LiveLogMessage): EventFormat => {
	const formatString = `${formattedLevelName(event.log_level)} ${event.driver_name}  ${event.message}`
	const time = event.timestamp

	return { formatString, time }
}

export const parseIpAndPort = (address: string): [string, string | undefined] => {
	const items = address.split(':')
	if (items.length > 2) {
		return fatalError('Invalid IPv4 address and port format.')
	}

	if (!net.isIPv4(items[0])) {
		return fatalError('Invalid IPv4 address format.')
	}

	const ipv4 = items[0]
	if (items.length == 1) {
		return [ipv4, undefined]
	}

	const port = Number(items[1])
	if (Number.isInteger(port) && port >= 0 && port <= 65535) {
		return [ipv4, port.toString()]
	}

	return fatalError('Invalid port format.')
}

export const handleConnectionErrors = (authority: string, error: string): never | void => {
	const generalMessage = 'Ensure hub address is correct and try again'

	if (error.includes('ECONNREFUSED') || error.includes('EHOSTUNREACH')) {
		return fatalError(`Unable to connect to ${authority}. ${generalMessage}`)
	}
	if (error.includes('ETIMEDOUT')) {
		return fatalError(`Connection to ${authority} timed out. ${generalMessage}`)
	}
	if (error.includes('EHOSTDOWN')) {
		return fatalError(`The host at ${authority} is down. ${generalMessage}`)
	}
}

export const networkEnvironmentInfo = (): string => inspect(os.networkInterfaces())

const scrubAuthInfo = (obj: unknown): string => {
	const message = inspect(obj)
	const bearerRegex = /(Bearer [0-9a-f]{8})[0-9a-f-]{28}/i

	if (bearerRegex.test(message)) {
		return message.replace(bearerRegex, '$1-xxxx-xxxx-xxxx-xxxxxxxxxxxx')
	} else { // assume there is some other auth format and redact the entire header value
		const authHeaderRegex = /'(Authorization: )([\s\S]*)'/i
		return message.replace(authHeaderRegex, '$1(redacted)')
	}
}

/**
 * Expected to manually verify the connected host (similar to overriding tls.checkServerIdentity)
 * by means that LiveLogClient isn't aware of ahead of time.
 */
export type HostVerifier = (cert: PeerCertificate) => Promise<void | never>

export type LiveLogClientConfig = {
	/**
	 * @example 192.168.0.1:9495
	 */
	authority: string
	authenticator: Authenticator
	verifier?: HostVerifier
	/**
	 * milliseconds
	 */
	timeout: number
	userAgent: string
}

export type LiveLogClient = {
	getDrivers(): Promise<DriverInfo[]>
	getLogSource(driverId?: string): string
}

export const newLiveLogClient = (config: LiveLogClientConfig): LiveLogClient => {
	const baseURL = new URL(`https://${config.authority}`)

	const driversURL = new URL('drivers', baseURL)
	const logsURL = new URL('drivers/logs', baseURL)
	let hostVerified = config.verifier === undefined

	const getCertificate = (response: AxiosResponse): PeerCertificate =>
		((response.request as ClientRequest).socket as TLSSocket).getPeerCertificate()

	const request = async (url: string, method: Method = 'GET'): Promise<AxiosResponse> => {
		const authHeaders = await config.authenticator.authenticate()
		const requestConfig = {
			url,
			method,
			httpsAgent: new https.Agent({ rejectUnauthorized: false }),
			timeout: config.timeout,
			// eslint-disable-next-line @typescript-eslint/naming-convention
			headers: { 'User-Agent': config.userAgent, ...authHeaders },
			transitional: {
				silentJSONParsing: true,
				forcedJSONParsing: true,
				// throw ETIMEDOUT error instead of generic ECONNABORTED on request timeouts
				clarifyTimeoutError: true,
			},
		}

		try {
			const response = await axios.request(requestConfig)

			if (!hostVerified && config.verifier) {
				await config.verifier(getCertificate(response))
				hostVerified = true
			}

			return response
		} catch (error) {
			if (error.isAxiosError) {
				const axiosError = error as AxiosError
				const cliLogger = log4js.getLogger('cli')
				if (cliLogger.isDebugEnabled()) {
					const errorString = scrubAuthInfo(axiosError.toJSON())
					cliLogger.debug(`Error connecting to live-logging: ${errorString}\n\nLocal network interfaces:` +
						` ${networkEnvironmentInfo()}`)
				}

				if (axiosError.code) {
					handleConnectionErrors(config.authority, axiosError.code)
				}
			}

			throw error
		}
	}

	const getDrivers = async (): Promise<DriverInfo[]> => (await request(driversURL.toString())).data

	const getLogSource = (driverId?: string): string => {
		const sourceURL = logsURL

		if (driverId) {
			sourceURL.searchParams.set('driver_id', driverId)
		}

		return sourceURL.toString()
	}

	return { getDrivers, getLogSource }
}

/**
 * This controls how every Server-sent event is formatted to the console in the CLI.
 */
const formatTimePrefix = '%s '

export type EventFormat = {
	/**
	 * A printf-like format string which can contain zero or more format specifiers.
	 */
	formatString: string

	/**
	 * Arguments that replace the corresponding specifiers in the formatString.
	 */
	formatArgs?: string[]

	/**
	 * The time the event was created.
	 */
	time: string
}

/**
 * A format function used to normalize the raw event data so that the CLI can log consistently.
 * Implementations are expected to return printf-like strings and args as well as event time.
 *
 * @param eventData Any instance of {@link MessageEvent.data}
 */
export type EventFormatter = (eventData: LiveLogMessage) => EventFormat

export const parseEvent = (event: MessageEvent): LiveLogMessage => {
	let message: unknown
	try {
		message = JSON.parse(event.data)
	} catch (error) {
		console.error(`Unable to parse received event. ${error.message ?? error}`)
	}

	if (isLiveLogMessage(message)) {
		return message
	} else {
		throw Error('Unexpected log message type.')
	}
}

/**
 * Log received Server-sent event data to the console.
 *
 * Aside from the event time which is logged first for all messages, format is specified by the
 * caller with a function that returns printf-like strings and args via {@link EventFormat}.
 *
 * @param message a message received by a target object
 * @param formatter a format function that controls how data is displayed
 */
export const logEvent = (message: LiveLogMessage, formatter: EventFormatter): void => {
	const eventFormat = formatter(message)
	const outputString = formatTimePrefix.concat(eventFormat.formatString)
	const outputArgs = eventFormat.formatArgs
		? [eventFormat.time].concat(eventFormat.formatArgs)
		: [eventFormat.time]

	console.log(outputString, ...outputArgs)
}
