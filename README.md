# Airia Python Examples

A collection of Python examples showing how to use Airia's API directly.

## Setup

```bash
pip install -r requirements.txt
```

Put your API key in a `.env` file in the repo root (`AIRIA_API_KEY=ak-...`) — each script loads it automatically via `python-dotenv`.

## Scripts

- [`on_demand.py`](api_examples/on_demand.py) — Upload a file for OnDemand processing
- [`sync_data_source.py`](api_examples/sync_data_source.py) — Trigger a sync on an existing data source
- [`agent_version_promote.py`](api_examples/agent_version_promote.py) — List an agent's pipeline versions and promote one to active
- [`pipeline_execution_feed.py`](api_examples/pipeline_execution_feed.py) — Fetch a pipeline's most recent execution and print each step's output

## Collections

Related APIs grouped by subdomain.

- [`custom_roles/`](api_examples/custom_roles/README.md) — List permissions, validate, and create custom roles
- [`groups/`](api_examples/groups/README.md) — List, create, update, and delete groups. Note that PUT replaces rather than merges.

## Multi-step examples

- [`role_group_sync/`](api_examples/role_group_sync/create_role_and_assign_group.py) — Create a custom role and merge it into an existing group's roles without clobbering them.
- [`file_upload_and_pipeline_execution.py`](api_examples/file_upload_and_pipeline_execution.py) — Upload a file and use it in an agent pipeline execution

## Other repos

- [Alyssa's repo](https://github.com/alyssagiuliano/airia_python_examples)
- [Reesy's repo](https://github.com/anthonygrees/airia_python_examples)