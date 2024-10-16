import {
	type SmartThingsClient,
	type SchemaApp,
	type SchemaAppRequest,
	type SmartThingsURLProvider,
	type ViperAppLinks,
} from '@smartthings/core-sdk'

import {
	booleanDef,
	createFromUserInput,
	type InputDefinition,
	listSelectionDef,
	maxItemValueLength,
	objectDef,
	optionalDef,
	optionalStringDef,
	staticDef,
	stringDef,
	updateFromUserInput,
} from '../../item-input/index.js'
import { clipToMaximum } from '../../util.js'
import { emailValidate, httpsURLValidate } from '../../validate-util.js'
import { type APICommand } from '../api-command.js'
import { organizationDef } from './organizations-util.js'
import { arnDef, webHookUrlDef } from './schema-util-input-primitives.js'
import { type ChooseFunction, createChooseFn } from './util-util.js'


export type SchemaAppWithOrganization = SchemaAppRequest & {
	organizationId?: string
}

// Create a type with some extra temporary fields.
export type InputData = SchemaAppWithOrganization & {
	includeAppLinks: boolean
}

export const validateFinal = (schemaAppRequest: InputData): true | string => {
	if ( schemaAppRequest.hostingType === 'lambda'
			&& !schemaAppRequest.lambdaArn
			&& !schemaAppRequest.lambdaArnEU
			&& !schemaAppRequest.lambdaArnAP
			&& !schemaAppRequest.lambdaArnCN) {
		return 'At least one lambda ARN is required.'
	}
	return true
}

export const appLinksDefSummarize = (value?: ViperAppLinks): string =>
	clipToMaximum(`android: ${value?.android}, ios: ${value?.ios}`, maxItemValueLength)

export const buildInputDefinition = async (
		command: APICommand,
		initialValue?: SchemaApp,
): Promise<InputDefinition<InputData>> => {
	// TODO: should do more type checking on this, perhaps using zod or similar
	const baseURL = (command.profile.clientIdProvider as SmartThingsURLProvider | undefined)?.baseURL
	const inChina = typeof baseURL === 'string' && baseURL.endsWith('cn')

	const hostingTypeDef = inChina
		? staticDef('lambda')
		: listSelectionDef('Hosting Type', ['lambda', 'webhook'], { default: 'webhook' })

	const appLinksDef = objectDef<ViperAppLinks>('App-to-app Links', {
		android: stringDef('Android Link'),
		ios: stringDef('iOS Link'),
		isLinkingEnabled: staticDef(true),
	}, { summarizeForEdit: appLinksDefSummarize })

	return objectDef<InputData>('Schema App', {
		organizationId: organizationDef(
			'Schema connector',
			await command.client.organizations.list(),
		),
		partnerName: stringDef('Partner Name'),
		userEmail: stringDef('User email', { validate: emailValidate }),
		appName: optionalStringDef('App Name', {
			default: (context?: unknown[]) =>
				(context?.[0] as Pick<SchemaAppRequest, 'partnerName'>)?.partnerName ?? '',
		}),
		oAuthAuthorizationUrl: stringDef('OAuth Authorization URL', { validate: httpsURLValidate }),
		oAuthTokenUrl: stringDef('Partner OAuth Refresh Token URL', { validate: httpsURLValidate }),
		icon: optionalStringDef('Icon URL', { validate: httpsURLValidate }),
		icon2x: optionalStringDef('2x Icon URL', { validate: httpsURLValidate }),
		icon3x: optionalStringDef('3x Icon URL', { validate: httpsURLValidate }),
		oAuthClientId: stringDef('Partner OAuth Client Id'),
		oAuthClientSecret: stringDef('Partner OAuth Client Secret'),
		oAuthScope: optionalStringDef('Partner OAuth Scope'),
		schemaType: staticDef('st-schema'),
		hostingType: hostingTypeDef,
		lambdaArn: arnDef('Lambda ARN for US region', inChina, initialValue),
		lambdaArnEU: arnDef('Lambda ARN for EU region', inChina, initialValue),
		lambdaArnCN: arnDef('Lambda ARN for CN region', inChina, initialValue, { forChina: true }),
		lambdaArnAP: arnDef('Lambda ARN for AP region', inChina, initialValue),
		webhookUrl: webHookUrlDef(inChina, initialValue),
		includeAppLinks: booleanDef('Enable app-to-app linking?', { default: false }),
		viperAppLinks: optionalDef(appLinksDef,
			(context?: unknown[]) =>
				(context?.[0] as Pick<InputData, 'includeAppLinks'>)?.includeAppLinks,
			{ initiallyActive: !!initialValue?.viperAppLinks }),
	}, { validateFinal })
}

const stripTempInputFields = (inputData: InputData): SchemaAppWithOrganization => {
	// Strip out extra temporary data to make the `InputData` into a `SchemaAppRequest`.
	// eslint-disable-next-line @typescript-eslint/no-unused-vars
	const { includeAppLinks, ...result } = inputData

	return result
}

export const getSchemaAppUpdateFromUser = async (
		command: APICommand,
		original: SchemaApp, dryRun: boolean,
): Promise<SchemaAppWithOrganization> => {
	const inputDef = await buildInputDefinition(command, original)

	const inputData = await updateFromUserInput(command, inputDef,
		{ ...original, includeAppLinks: !!original.viperAppLinks }, { dryRun })

	return stripTempInputFields(inputData)
}

export const getSchemaAppCreateFromUser = async (
		command: APICommand,
		dryRun: boolean,
): Promise<SchemaAppWithOrganization> => {
	const inputDef = await buildInputDefinition(command)

	const inputData = await createFromUserInput(command, inputDef, { dryRun })

	return stripTempInputFields(inputData)
}

export const chooseSchemaAppFn = (): ChooseFunction<SchemaApp> => createChooseFn(
	{
		itemName: 'schema app',
		primaryKeyName: 'endpointAppId',
		sortKeyName: 'appName',
	},
	(client: SmartThingsClient): Promise<SchemaApp[]> => client.schema.list(),
)

export const chooseSchemaApp = chooseSchemaAppFn()