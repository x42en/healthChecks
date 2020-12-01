const fs = require('fs')
const { join } = require('path')

// Get the package obejct and change the name
const pkg = require('../package.json')
pkg.name = '@x42en/healthchecks-external'

// Update package.json with the udpated name
fs.writeFileSync(join(__dirname, '../package.json'), JSON.stringify(pkg))