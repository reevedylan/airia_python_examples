# Airia Python Examples

This repository contains a collection of Python examples showing how to use Airia's API.

## API Examples
A collection of Python examples demonstrating direct usage of Airia's API.

- [`on_demand.py`](api_examples/on_demand.py) - Uploads a file for OnDemand Processing.
- [`sync_data_source.py`](api_examples/sync_data_source.py) - Basic setup and simple API calls
- [`file_upload_and_pipeline_execution.py`](api_examples/file_upload_and_pipeline_execution.py) - Uploads a file for use within an agent pipeline's execution.
- [`custom_roles/`](api_examples/custom_roles/README.md) - List permissions, validate, and create custom roles. See the folder's README for the (undocumented) request/response shapes.
- [`groups/`](api_examples/groups/README.md) - List, create, update, and delete groups. See the folder's README for the (undocumented) request/response shapes, including a PUT-replaces-not-merges gotcha.
- [`role_group_sync/create_role_and_assign_group.py`](api_examples/role_group_sync/create_role_and_assign_group.py) - Creates a custom role and attaches it to an existing group, merging it into the group's current roles instead of clobbering them. Prototype for a future CI/CD (Okta SCIM sync) workflow.

## Airia Team Repos

Looking for more? Check out the rest of the team's repos!

- [Alyssa's Repo](https://github.com/alyssagiuliano/airia_python_examples)
- [Reesy's Repo](https://github.com/anthonygrees/airia_python_examples)