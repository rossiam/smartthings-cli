const shared = require('../../.eslintrc.js')

shared.parserOptions.tsconfigRootDir = __dirname
shared.ignorePatterns = [
	'src/api-command.ts',
	'src/__tests__/api-command.test.ts',
	'src/api-organization-command.ts',
	'src/__tests__/api-organization-command.test.ts',
	'src/basic-io.ts',
	'src/__tests__/basic-io.test.ts',
	'src/command-util.ts',
	'src/__tests__/command-util.test.ts',
	'src/common-flags.ts',
	'src/device-util.ts',
	'src/__tests__/device-util.test.ts',
	'src/format.ts',
	'src/__tests__/format.test.ts',
	'src/input.ts',
	'src/__tests__/input.test.ts',
	'src/input-builder.ts',
	'src/__tests__/input-builder.test.ts',
	'src/listing-io.ts',
	'src/__tests__/listing-io.test.ts',
	'src/login-authenticator.ts',
	'src/__tests__/login-authenticator.test.ts',
	'src/output.ts',
	'src/__tests__/output.test.ts',
	'src/output-builder.ts',
	'src/__tests__/output-builder.test.ts',
	'src/select.ts',
	'src/__tests__/select.test.ts',
	'src/smartthings-command.ts',
	'src/__tests__/smartthings-command.test.ts',
	'src/__tests__/test-lib/mock-command.ts',
	'src/sse-command.ts',
	'src/__tests__/sse-command.test.ts',
	'src/sse-io.ts',
	'src/__tests__/sse-io.test.ts',

	'src/item-input/command-helpers.ts',
	'src/__tests__/item-input/command-helpers.test.ts',
]

module.exports = shared
