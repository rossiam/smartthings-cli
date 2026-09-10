import { type ArgumentsCamelCase, type Argv, type CommandModule } from 'yargs'

import {
	type PagedSmartApp,
	type SmartAppClassification,
	smartAppClassificationValues,
	type SmartAppListOptions,
	type SmartAppResponse,
	type ViewSmartAppType,
	viewSmartAppTypeValues,
} from '@smartthings/core-sdk'

import { buildEpilog } from '../lib/help.js'
import { type TableFieldDefinition } from '../lib/table-generator.js'
import {
	apiOrganizationCommand,
	apiOrganizationCommandBuilder,
	type APIOrganizationCommandFlags,
} from '../lib/command/api-organization-command.js'
import {
	type OutputItemOrListConfig,
	type OutputItemOrListFlags,
	outputItemOrList,
	outputItemOrListBuilder,
} from '../lib/command/listing-io.js'
import { tableFieldDefinitions } from '../lib/command/util/smartapps-table.js'
import { shortARNorURL, verboseSmartApps } from '../lib/command/util/smartapps-util.js'


export type CommandArgs = APIOrganizationCommandFlags & OutputItemOrListFlags & {
	type?: ViewSmartAppType
	classification?: SmartAppClassification[]
	verbose: boolean
	idOrIndex?: string
}

const command = 'smartapps [id-or-index]'

const describe = 'get a specific Smart App or a list of Smart Apps'

const builder = (yargs: Argv): Argv<CommandArgs> =>
	outputItemOrListBuilder(apiOrganizationCommandBuilder(yargs))
		.positional('id-or-index', { describe: 'the Smart App id or number from list', type: 'string' })
		.option('type', {
			describe: 'filter results by Smart App type',
			type: 'string',
			choices: viewSmartAppTypeValues,
			coerce: arg => arg.toUpperCase() as ViewSmartAppType,
		})
		.option('classification', {
			describe: 'filter results by one or more classifications',
			type: 'string',
			array: true,
			choices: smartAppClassificationValues,
			coerce: arg => arg?.map((str: string) => str.toUpperCase() as SmartAppClassification),
		})
		.option('verbose',
			{ alias: 'v', describe: 'include URLs and ARNs in table output', type: 'boolean', default: false })
		.example([
			['$0 smartapps', 'list all Smart Apps'],
			[
				'$0 smartapps 1',
				'display details for the first smart app in the list retrieved by running "smartthings smartapps"',
			],
			['$0 smartapps 5dfd6626-ab1d-42da-bb76-90def3153998', 'display details for a Smart App by id'],
			['$0 smartapps --verbose', 'include URLs and ARNs in the output'],
			['$0 smartapps --classification SERVICE', 'list SERVICE classification Smart Apps'],
			['$0 smartapps --type API_ONLY', 'list API-only Smart Apps'],
		])
		.epilog(buildEpilog({ command, apiDocs: ['listSmartApps', 'getSmartApp'] }))

const handler = async (argv: ArgumentsCamelCase<CommandArgs>): Promise<void> => {
	const command = await apiOrganizationCommand(argv)

	const listTableFieldDefinitions: TableFieldDefinition<PagedSmartApp | SmartAppResponse>[] =
		['displayName', 'appType', 'appId']
	if (argv.verbose) {
		listTableFieldDefinitions.push({ label: 'Target URL or ARN', value: shortARNorURL })
	}
	const config: OutputItemOrListConfig<SmartAppResponse, PagedSmartApp | SmartAppResponse> = {
		primaryKeyName: 'appId',
		sortKeyName: 'displayName',
		tableFieldDefinitions,
		listTableFieldDefinitions,
	}

	const listApps = async (): Promise<PagedSmartApp[] | SmartAppResponse[]> => {
		const appListOptions: SmartAppListOptions = {}
		const accountId = command.client.config.headers?.['X-ST-Organization']
		if (accountId) {
			appListOptions.accountId = accountId
		}

		if (argv.type) {
			appListOptions.appType = argv.type
		}

		if (argv.classification) {
			appListOptions.classification = argv.classification
		}

		if (argv.verbose) {
			return verboseSmartApps(command.client, appListOptions)
		}
		return command.client.smartapps.list(appListOptions)
	}

	await outputItemOrList(command, config, argv.idOrIndex, listApps, id => command.client.smartapps.get(id))
}

const cmd: CommandModule<object, CommandArgs> = { command, describe, builder, handler }
export default cmd
