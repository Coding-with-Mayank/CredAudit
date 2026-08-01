<!-- CAST Imaging MCP v1.3.0 -->
---
applyTo: '**'
---
General instructions for correct usage of Imaging tools (may begin with a suffix like `bb7_`).
These instructions apply to all AI copilot providers in VS Code, including GitHub Copilot, Claude, and others.

# Important information
The model should ALWAYS run `applications` tool when using Imaging tools. The model should never recommend that the user uses the tools. Only the model can use them.

Imaging tools are a way of obtaining software intelligence: architectural information key to understanding applications. They help find information about dependencies, packages, caller/callee relationships, and transactions/data calls between user inputs and databases.

When asked questions related to software, technology, applications, or projects, you should reference imaging tools. You should begin by running the `applications` tool to identify the correct application in Imaging. Even if a repo is currently open, you should run `applications` to match the correct application as naming convention may have changed.

The model should not ask the user "do you want me to use the tools" or "would you like me to proceed" but rather act with the tools. This is to be more concise. Unless asked explicitly by the user, the assistant/agent/model should go ahead and use the tools.

There are two major ways of using imaging tools for users: exploration and impact mode.
1) Exploration mode is for dealing with whole applications: understanding overall architecture or architecture of samples of the application and its transactions/data calls.
2) Impact analysis mode when dealing with code elements directly to understand direct/indirect dependencies and understand how the elements fit in the software structure.

If a user does not have an application open in the current repository, they may be looking at portfolio level queries. Portfolio level questions are questions across multiple applications. Verify this is the case with the user.

# Information about imaging
This is a set of information about naming convention behind Imaging:

## Graphs and links
Most information in Imaging is stored as Graphs behind the scenes. You can specify that you want element information or information about the links representing the relationships between elements.

## Transactions and Data Call Graphs
Transaction and Data Call Graph are based on vertical call graphs starting from an Input (Interface, batch, Web UI element etc.) down to an output (table, file, API call etc.) for Transaction and vice versa for Data Call Graph (from an output to an input).

## Objects
Objects are the lowest level abstraction in imaging: they represent the smallest unit of code (classes for example). You can retrieve higher level information by changing granularity within specific tools.

# Impact Analysis

Impact analysis is one of the 2 major use cases of imaging tools. Impact analysis involves understanding the potential effects and dependencies of changes to specific objects, components, or areas within an application or portfolio. You should intelligently perform impact analysis before editing code to have additional context and avoid mistakes. You should also perform one after edits for information about useful tests and affected sections of the application.

The model should not ask the user "do you want me to perform an impact analysis" but rather perform it when appropriate on its own.

# Recommended tools
These tools are a set of recommended (although not exhaustive) tools that can aid in analyzing impact and dependencies. You should use these tools before others when answering impact-related questions:
- `object_details`
- `transactions_using_object`
- `data_graphs_involving_object`
- `inter_applications_dependencies`

This isn't an exhaustive list, but these tools are the most important ones to trace dependencies and understand impact chains. You want to identify the current object with imaging tool and use the 4 tools recommended here for. For impact analysis queries, focus on mapping relationships and dependencies before diving into source code modifications; use the imaging tools to build a comprehensive view of what will be affected by proposed changes. Importantly, you may want to consider what other sections of code will be impacted, which databases, which technologies, etc...

# Edit process

When modifying code directly:
**before** the modification you suggest: use context to better design the modification, trying - if not stated otherwise by the user - to minimize / avoid altogether breaking changes,
**after** the modification you suggest: use context to:
- at minimum, inform the user of 1. existing dependencies the user should take care of and 2. existing transactions that should be tested,
- ideally, suggest additional modifications to 1. repair the breaking changes, recursively in the call graph if needed, and 2. update test cases, run test cases (if possible)

When dealing with code elements of applications:
- use quality_insight_occurrences to find code objects manifesting specific quality issues within the codebase.
- use object_details to know more about the code objects to fix/replace/...
- use object_details on dependent code objects to check/fix/replace/...
- use transactions_using_object on all the updated code objects and consolidate the different transactions that will have to be tested after the changes.
- use datagraphs_involving_object on all the updated code objects and consolidate the different datagraphs that will have to be checked after the changes.
tip: use packages to get external packages and libraries already in use in the application to get ideas for easier fix.

# Exploration

Exploration is one of the 2 major use cases of imaging tools. Exploration is any sort of general question a user might have about a whole application or portfolio.

# Common queries
Common queries in instruction mode:
- How to migrate technology?
- What are current safety issues in my app? What are the most important ones to fix?
- Summarize my application and its technologies.
- What are the main sections of my application?

# Recommended tools
These tools are a set of recommended (although not exhaustive) tools that can aid in answering user queries. You should use these tools before others when answering such large-scale questions:
- `applications`
- `stats`
- `architectural_graph`
- `quality_insights`
- `packages`

This isn't an exhaustive list, but these tools are the most important ones to get wide-scale information quickly. For exploration queries, avoid going into source/raw code too quickly; instead focus on the imaging tools to answer questions with a high level view of the application.

# Portfolio exploration
Portfolio exploration is a specific type of exploration where the user either doesn't have any repository open or wants to know more about cross-application information (or early exploration like finding the right applications).

If a user asks question about interactions between applications, use the tools that start with `applications`. Sample user query: "How does my `Shopping` app interact with my `Photo` app?".
The portfolio tools are: 
- `applications`
- `applications_transactions`
- `applications_data_graphs`
- `applications_dependencies`
- `applications_quality_insights`

# Fallback Handling
When encountering queries that are completely outside the scope of imaging and software analysis (such as jokes, weather, general knowledge, entertainment, or personal questions), use the `fallback_irrelevant` tool. This ensures the model stays focused on its primary purpose while gracefully handling off-topic requests.

# Custom Aggregation (Custom Views)

Custom aggregation allows users to create personalized views that group objects based on specific criteria. This is useful for organizing and analyzing objects by transactions, types, quality issues, or naming patterns.

## When to use
Use custom aggregation when users want to:
- Create custom groupings of objects for analysis
- Organize objects by specific criteria (transactions, types, insights)
- Build reusable views for recurring analysis tasks
- Share curated views with team members

## Recommended tools
- `custom_views` - Manage custom views (create, list, get, delete, update, publish, unpublish)
- `custom_node` - Add nodes to views with specific filter criteria

## CRITICAL WORKFLOW (MUST FOLLOW)

**ALWAYS call the appropriate tool FIRST to get exact values before creating custom nodes.**

1. **Create a view**: Use `custom_views` with focus='create' and a view_name

2. **Get filter values** (MANDATORY - do not skip):
   - **For transaction filter**: MUST call `transactions(application="<app_name>")` tool
   - **For object_type filter**: MUST call `object_profiles(application)` tool first
   - **For insight filter**: Just provide `insight_category` - rules are ALWAYS auto-fetched from API!

3. **Add nodes**: Use `custom_node` with the view_id and filter criteria

4. **View results**: Use `custom_views` with focus='get' to see the aggregated view

# Migration & Modernization

Migration and modernization analysis helps identify code patterns that need attention when moving to new platforms (AWS, Azure, GCP) or modernizing technology (.NET, database migration).

# Recommended tools
- `advisors` (with focus="list")
- `advisors` (with focus="rules", advisor_id=...)
- `advisors` (with focus="violations", advisor_id=..., rule_id=...)