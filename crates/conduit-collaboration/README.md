# conduit-collaboration

Control-plane domain and services for Project Agents, immutable Board Message revisions, Assignments, orchestration, Tasks, and bounded Context Snapshots.

Only a structured `MentionIntent::Assignment` submitted through `post_assignment` can create an Assignment. The Message and Assignment are validated and inserted under one store lock. Plain posts, imports, quotes, code blocks, and edits cannot start Agents.

Agent roles enforce Source permissions; Assignment transitions retain history; handoffs enforce deterministic depth, cycle, cost, time, Run-count, and per-Agent concurrency limits. Task dependency updates reject cycles.

The Context Compiler prioritizes explicit Project, Session, Assignment, Message, Source, Change Set, Artifact, instruction, and Skill candidates under item and byte limits. Every typed input gets an immutable digest. Instruction discovery records relative display paths and opaque path hashes, never shareable canonical paths.

