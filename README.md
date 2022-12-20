# ⛅ Airtable API and proxy 

Airtable.do is an all new API interface for Airtable that uses the new OAuth method to allow you to setup multiple accounts and interact with them all.

## Security
Airtable.do uses an API key system to scope access to your data from external sources. Visit your namespace's route to generate and manage your API keys. You can also restrict API keys to only being able to read or write to your bases.

## Routes
#### GET `/:namespace/claim`
Visiting this route will claim the namespace for your account. This is needed to allow for multiple accounts to be used with airtable.do. You will be redirected to Airtable which will ask you what bases you want to link to our API.

#### GET `/:namespace`
Returns the configuration for the namespace. This includes the API keys and the bases that are linked to the namespace.

#### GET `/:namespace/bases/:baseIDorName`
This will return all the tables in the base. You can also use the base name instead of the base ID.

#### GET `/:namespace/bases/:baseIDorName/tables/:tableIDorName`
This will return all the records in the table. Please refer to the Airtable API documentation for more information on how to use the query parameters.
[Documentation](https://airtable.com/api)

#### GET `/:namespace/bases/:baseIDorName/tables/:tableIDorName/export`
This will return all the records in the table as a JSONL file. This file is used for PITR (Point in Time Recovery) and can be used to restore the table to a previous state. To be used with the import URL route.

#### GET `/:namespace/bases/:baseIDorName/import`
This will import a JSONL file into the table. This file is used for PITR (Point in Time Recovery) and can be used to restore the table to a previous state. To be used with the export URL route.

#### POST `/:namespace/bases/:baseIDorName/tables/:tableIDorName`
This will create a new record in the table. JSON body is used to create the records, with the same parameters supported as the Airtable API.

e.g.

```bash
curl -X POST \
  https://airtable.do/airtable/bases/app123/tables/Table%201 \
  -H 'Content-Type: application/json' \
  -d '{
  "fields": {
    "Name": "John Doe",
    "Age": 30
  }
}'
```