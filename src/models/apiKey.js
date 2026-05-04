const { Sequelize, DataTypes } = require('sequelize');
const sequelize = require('../db/sequelize');
const { Organization } = require('./organization');

const DPAPIKey = sequelize.define(
    'DP_API_KEY',
    {
        API_KEY_ID: {
            type: DataTypes.STRING,
            primaryKey: true
        },
        ORG_ID: {
            type: DataTypes.STRING,
            allowNull: false
        },
        USER_ID: {
            type: DataTypes.STRING,
            allowNull: false
        },
        NAME: {
            type: DataTypes.STRING,
            allowNull: false
        },
        KEY_HASH: {
            type: DataTypes.STRING,
            allowNull: false
        },
        SCOPES: {
            type: DataTypes.STRING(1024),
            allowNull: false,
            validate: {
                is: /^[^\s]+(?: [^\s]+)*$/
            }
        },
        STATUS: {
            type: DataTypes.ENUM('ACTIVE', 'REVOKED', 'EXPIRED'),
            allowNull: false,
            defaultValue: 'ACTIVE'
        },
        CREATED_AT: {
            type: DataTypes.DATE,
            allowNull: false,
            defaultValue: Sequelize.NOW
        },
        EXPIRED_AT: {
            type: DataTypes.DATE,
            allowNull: false
        }
    },
    {
        timestamps: false,
        tableName: 'DP_API_KEY',
        indexes: [
            {
                // for filter the API keys based on organization, user and status
                fields: ['ORG_ID', 'USER_ID', 'STATUS']
            },
            {
                unique: true,
                fields: ['KEY_HASH']
            }
        ]
    }
);

DPAPIKey.belongsTo(Organization, {
    foreignKey: 'ORG_ID'
});

module.exports = DPAPIKey;
