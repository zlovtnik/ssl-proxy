export const email = 'rafael@rclabs.uk';

export const author = {
  name: 'Rafael Cardoso',
  profile: 'https://github.com/zlovtnik',
  privacyEmail: email,
} as const;

const professionalHeadline =
  'Senior Software Engineer | Backend Systems & Enterprise Integration';

export const accessibility = {
  title: 'Accessibility',
  summary:
    'The site is being evaluated against WCAG 2.2 A, AA, and AAA criteria. I do not currently claim conformance.',
} as const;

export const hiring = {
  pageTitle: 'Contact Rafael.',
  pageSummary:
    'Hiring for a senior backend, integration, or data-pipeline role? Email me about the role and the engineering team.',
  eyebrow: 'CONTACT',
  projectsTitle: 'Project questions',
  projectsSummary:
    'Source and regression tests are linked from each project writeup.',
  projectPrompt:
    'For a technical interview, mention the project or failure mode you would like to discuss.',
  addressTitle: 'Email address',
  addressSummary: 'You can also write to me directly.',
  cta: 'Contact',
  href: `mailto:${email}?subject=${encodeURIComponent('General inquiry')}&body=${encodeURIComponent('Hello Rafael,\n\nI would like to get in touch about:\n\nThank you.')}`,
  resume: { label: 'Read my resume', href: '/resume/' },
  title: 'Backend engineering roles',
  summary:
    'I’m in Portland, Maine, open to remote or hybrid work, and authorized to work in the U.S. without sponsorship.',
} as const;

const octopusTests = 'services/octopus/src/test/scala/com/sslproxy/coordinator';

export const portfolio = {
  audience:
    'Independent backend systems, with source code, failure cases, and regression tests.',
  experience: {
    label: 'Professional experience',
    employer: 'Synchro',
    summary:
      'I designed and supported a Java, Spring Boot, and Apache Camel integration between Oracle ERP Cloud, electronic invoicing, and tax systems. It processed approximately 20 million fiscal transactions per week. I later led architecture and code reviews for teams of 3 to 8 engineers.',
    attribution:
      'Approximate historical Synchro workload, separate from the independent RCLabs projects.',
    aboutLink: { label: 'Read about my work', href: '/about/#experience' },
  },
  workTitle: 'Selected engineering work',
  workSummary:
    'Projects I built independently of my Synchro employment. Each includes a failure case, implementation details, and regression tests.',
  projects: [
    {
      id: 'octopus',
      title: 'Octopus',
      kind: 'Independent project / Scala, Cats Effect, PostgreSQL',
      built:
        'I built the durable ingestion coordinator: broker-coordinate evidence, persisted event/job/batch state, processor status, deduplication, leases, and fenced outbox dispatch.',
      failure:
        'A process can stop after a database write or broker acknowledgement but before progress is committed. Delivery repeats, while one failed record can sit beside healthy work in the same batch.',
      response:
        'Persist scan-request state and ingestion evidence in one PostgreSQL transaction, reject changed payloads for an existing identity, and commit Kafka offsets only after durable handling. Restarts resume from committed group offsets. Stable dispatch keys and receiving-side deduplication tolerate the outbox acknowledgement/crash window. Expiring fenced leases reclaim work without authorizing stale completion.',
      tested:
        'Repository tests cover persisted processor state, duplicate replay, changed-payload rejection, concurrent outbox claims, healthy peers surviving a permanent result failure, and completion waiting for every batch. PostgreSQL integration tests require Docker and can skip when it is absent.',
      unverified:
        'These tests do not establish recovery time or a complete broker/database/process-crash campaign. At-least-once delivery can repeat. There is no exactly-once or zero-loss guarantee. Live ledger counts do not establish capacity.',
      decisions: [
        [
          'PostgreSQL ledger with manual offset commits',
          'Kafka transactions alone cannot atomically commit the PostgreSQL sink. Persisting state before the offset commit leaves a replay window, which durable deduplication must handle.',
        ],
        [
          'Expiring leases with fencing',
          'A lease can expire while its worker still runs. The fence rejects that worker’s completion after replacement, rather than relying on expiry alone.',
        ],
        [
          'Reject changed payloads for an existing identity',
          'Last-write-wins would conceal conflicting input behind a successful replay. Rejection preserves the original identity and makes the conflict visible.',
        ],
      ],
      links: [
        {
          label: 'Persistence implementation',
          href: repositorySource(
            'services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/PostgresRepository.scala',
          ),
        },
        {
          label: 'Replay and recovery integration tests',
          href: repositorySource(
            `${octopusTests}/ingest/OctopusPersistenceIntegrationSuite.scala`,
          ),
        },
        {
          label: 'Partial-failure tests',
          href: repositorySource(
            `${octopusTests}/kafka/PostgresLoadStreamSuite.scala`,
          ),
        },
        {
          label: 'Result dead-letter handling tests',
          href: repositorySource(
            `${octopusTests}/kafka/PostgresResultStreamSuite.scala`,
          ),
        },
        {
          label: 'Processor persistence tests',
          href: repositorySource(
            `${octopusTests}/processor/ProcessorSupervisorSuite.scala`,
          ),
        },
        {
          label: 'OpenTelemetry instrumentation',
          href: repositorySource(
            'services/octopus/src/main/scala/com/sslproxy/coordinator/observability/CoordinatorTracing.scala',
          ),
        },
        {
          label: 'Payload archive verification',
          href: repositorySource(
            'services/octopus/src/main/scala/com/sslproxy/coordinator/archive/PayloadArchive.scala',
          ),
        },
        { label: 'Octopus workflow and live readings', href: '/octopus/' },
      ],
    },
    {
      id: 'search',
      title: 'Atheros Search',
      kind: 'Independent project / Go, PostgreSQL, SolidJS',
      built:
        'I built the retrieval service, leased embedding workers, and console for inspecting semantic, keyword, and fused search scores across source observations.',
      failure:
        'An expired worker can finish after a replacement has claimed its job, publishing stale vectors. A failed embedding provider can also make the semantic search leg unavailable.',
      response:
        'Fence completion with lease tokens and content revisions, write vectors and job completion in one transaction, and expose a labelled sparse fallback when hybrid retrieval cannot use its semantic leg.',
      tested:
        'Repository tests cover weighted reciprocal-rank fusion and deduplication, explicit fallback codes, lost-lease rollback, vector-write failure rollback, and stale-fence rejection against PostgreSQL.',
      unverified:
        'No published relevance benchmark or latency result. Wireless observations and identity candidates do not confirm a current connection or physical device identity. The public sample is synthetic.',
      decisions: [
        [
          'Fuse ranks rather than raw scores',
          'Keyword and vector scores have different scales. Weighted reciprocal-rank fusion combines their positions, with configurable weights. Its relevance still needs a labelled benchmark.',
        ],
        [
          'Label sparse fallback',
          'When embeddings are unavailable, keyword evidence remains useful. The response identifies the degraded mode so a caller can distinguish it from a complete hybrid result.',
        ],
        [
          'Complete vectors and jobs in one transaction',
          'Separate commits could publish a vector without completing its job, or complete the job without its vector. Lease and revision checks keep stale workers from committing either.',
        ],
      ],
      links: [
        {
          label: 'Retrieval fusion implementation',
          href: repositorySource(
            'apps/integration-console/atheros-search/internal/search/fusion.go',
          ),
        },
        {
          label: 'Atomic worker completion tests',
          href: repositorySource(
            'apps/integration-console/atheros-search/internal/worker/worker_transaction_test.go',
          ),
        },
        {
          label: 'Embedding circuit-breaker tests',
          href: repositorySource(
            'apps/integration-console/atheros-search/internal/embed/circuit_test.go',
          ),
        },
        { label: 'Atheros Search case study', href: '/atheros-search/' },
      ],
    },
    {
      id: 'migrator',
      title: 'Schema Migrator',
      kind: 'Independent tooling / Scala, Cats Effect',
      built:
        'I built ordered SQL-file validation and planning, run records, and a review workflow that keeps offline checks separate from database execution.',
      failure:
        'Ambiguous dependencies can produce an unsafe apply order. A failed or cancelled run can leave ownership behind and block recovery.',
      response:
        'Reject duplicate, missing, or cyclic dependencies before apply. Scope lock release to the protected action and cancel managed work so a started run can be recovered durably.',
      tested:
        'Repository tests cover invalid dependency plans, rejection before apply, lock release after failure, and cancellation releasing a started run for durable recovery.',
      unverified:
        'Offline checks do not establish target permissions, lock behavior, or reversibility of arbitrary DDL. SQL-file snapshots preserve source files and checksums. They do not back up database data. The sample executes no SQL.',
      links: [
        {
          label: 'Migration planning tests',
          href: repositorySource(
            'apps/schema-migrator/src/test/scala/com/sslproxy/schema/engine/MigrationPlanSuite.scala',
          ),
        },
        {
          label: 'Run recovery tests',
          href: repositorySource(
            'apps/schema-migrator/src/test/scala/com/sslproxy/schema/server/RunExecutorSupervisorSuite.scala',
          ),
        },
        { label: 'Schema Migrator walkthrough', href: '/schema-migrator/' },
      ],
    },
    {
      id: 'vpn',
      title: 'RCLabs VPN / Proxy',
      kind: 'Independent project / Rust, WireGuard',
      built:
        'I built the transparent proxy path for WireGuard traffic, classification, and audit-event publishing into the ingestion pipeline.',
      failure:
        'Hostname suffix mistakes, fragmented headers, or reused HTTP connections can bypass request checks. Incomplete TLS metadata can also lead to an overconfident classification.',
      response:
        'Match domain boundaries explicitly, check each plaintext request before connecting upstream, and distinguish partial TLS ClientHello parsing from complete evidence.',
      tested:
        'Repository tests cover exact suffix matches, fragmented blocked HTTP headers, per-request keepalive checks, missing SNI, and fragmented or incomplete TLS handshakes.',
      unverified:
        'No Internet-wide classification accuracy, device-interoperability, or production-throughput claim. Traffic outside the configured path is not covered. The browser sample opens no VPN connection.',
      links: [
        {
          label: 'Classification implementation and tests',
          href: repositorySource('src/tunnel/classify.rs'),
        },
        {
          label: 'Transparent proxy regression tests',
          href: repositorySource('src/tunnel/transparent_tests.rs'),
        },
        { label: 'VPN / Proxy walkthrough', href: '/vpn-proxy/' },
      ],
    },
  ],
  evidence: {
    title: 'Source, tests, and live readings',
    summary:
      'The project code is public. Employer workload, project measurements, and browser examples describe different things.',
    categories: [
      {
        title: 'Historical employer work',
        text: 'Synchro roles and workload are career context from my resume. Employer implementation and monitoring are not available in this repository.',
      },
      {
        title: 'Independent project evidence',
        text: 'Source and regression tests expose implementation choices. Octopus runtime readings measure this independent deployment: ledger activity, backlog, and freshness, not unique business transactions or a capacity benchmark.',
      },
      {
        title: 'Synthetic demonstrations',
        text: 'Search, Migrator, and VPN / Proxy examples run in your browser. They demonstrate interfaces and review steps, not production load, customer adoption, or measured outcomes.',
      },
    ],
    metrics: {
      label: 'Octopus metrics and measurement definitions',
      href: '/octopus/#operational-evidence',
    },
  },
} as const;

export const resume = {
  title: 'Rafael Cardoso - Resume',
  role: professionalHeadline,
  location: 'Portland, ME | Open to Remote / Hybrid',
  authorization: 'Authorized to work in the U.S. | No sponsorship required',
  email,
  website: {
    label: 'rclabs.uk',
    href: 'https://rclabs.uk/',
  },
  linkedin: {
    label: 'linkedin.com/in/racasantos',
    href: 'https://linkedin.com/in/racasantos',
  },
  summary:
    'Senior Software Engineer with 15+ years in software and enterprise integrations. Designed and supported Java, Spring Boot, and Apache Camel fiscal integrations at Synchro. Builds independent Scala and Go systems for event ingestion, recovery, and hybrid search.',
  skills: [
    [
      'Backend',
      'Java, Spring Boot, Scala, Go, SQL, PostgreSQL, Oracle Database',
    ],
    [
      'Distributed Systems',
      'Scala 3, Cats Effect, FS2, Kafka API via Redpanda, idempotency, backpressure, retries, recovery',
    ],
    [
      'Platform',
      'Kubernetes, Docker, Kustomize, Argo CD, GitOps, CI/CD, OpenTelemetry, Prometheus, Grafana',
    ],
    [
      'Technical Leadership',
      'Architecture reviews, code reviews, release validation, production diagnosis',
    ],
    ['Additional', 'Rust, PL/SQL, Apache Camel'],
  ],
  positions: [
    {
      title: 'Independent engineering (self-directed)',
      company: 'RCLabs',
      period: 'September 2024 - Present',
      points: [
        'Built Go and Scala backend services with PostgreSQL and Redpanda, using durable processing and recovery to handle interrupted work.',
        'Configured Kubernetes GitOps delivery with Kustomize, digest-pinned images, and Argo CD. Rollback follows a Git revert. Instrumented Octopus with OpenTelemetry.',
      ],
    },
    {
      title: 'Senior Staff Software Engineer',
      company: 'Synchro',
      period: 'May 2022 - September 2024',
      points: [
        'Led architecture and code reviews for teams of 3 to 8 engineers delivering fiscal and enterprise integrations.',
        'Built Go retrieval-augmented generation and Python machine learning components for a 2024 customer project involving electronic invoice recognition and fiscal data consolidation. Used Oracle Integration Cloud and OCI AI capabilities for fiscal data preparation.',
        'Turned recurring production failures into reusable validation checks and integration design rules across client projects.',
        'Standardized CI/CD scripts and expanded automated tests across several services to make release verification repeatable and simplify failure diagnosis.',
      ],
    },
    {
      title: 'Senior Software Engineer',
      company: 'Synchro',
      period: 'September 2018 - May 2022',
      points: [
        'Designed and supported a Java/Spring Boot and Apache Camel integration processing approximately 20 million fiscal transactions per week between Oracle ERP Cloud, electronic invoicing, and tax systems.',
        'Processed 1-2 GB XML documents from Oracle ERP Cloud SOAP services using PL/SQL and XSLT, with fault recovery, replayable processing, and durable transaction handling.',
        'Integrated Oracle Retail Fiscal Management with Synchro products and resolved fiscal data discrepancies across client deployments.',
        'Produced validation evidence for engineering, client, and commercial teams to confirm data correctness and release readiness.',
      ],
    },
    {
      title: 'Software Analyst',
      company: 'Synchro',
      period: 'February 2011 - September 2018',
      points: [
        'Translated Brazilian tax rules, electronic filing requirements, and banking integration needs into software specifications for enterprise implementations.',
        'Traced data discrepancies, validated product behavior, and produced reports covering correctness, performance, and regulatory requirements.',
      ],
    },
  ],
  independent: {
    title: 'Independent engineering (self-directed)',
    period: 'September 2024 onward',
    summary:
      'Since September 2024 I have built Octopus durable ingestion, Atheros Search retrieval and embedding workers, the Rust VPN / Proxy, and Schema Migrator independently through RCLabs.',
  },
  projects: [
    {
      title: 'Octopus Event Ingestion Coordinator',
      href: '/#case-octopus',
      technologies: 'Scala 3, Cats Effect, FS2, Kafka/Redpanda, PostgreSQL',
      points: [
        'Built an event ingestion coordinator with PostgreSQL-backed deduplication and durable offset tracking for at-least-once Kafka/Redpanda processing.',
        'Added backpressure, bounded retries, and dead-letter handling to recover failed work and control processing load.',
        'Instrumented processing with OpenTelemetry and archived large payloads in MinIO with hash and size metadata checks.',
      ],
    },
    {
      title: 'Atheros Search and Integration Console',
      href: '/#case-search',
      technologies: 'Go, PostgreSQL, pgvector',
      points: [
        'Built a Go service for hybrid semantic and keyword retrieval over operational records using PostgreSQL and pgvector.',
        'Implemented recoverable embedding jobs with configurable backends, retries, caching, and circuit breaking.',
        'Developed a console that explains search rankings and displays access-point risk scores derived by Octopus.',
      ],
    },
  ],
  education: [
    'M.S., Data Analysis - Universidade Nove de Julho, 2020',
    'B.S., Computer Science - Faculdades Metropolitanas Unidas, 2011',
  ],
  print: 'Print or save as PDF',
} as const;

export const delivery = {
  title: 'How I ship',
  summary:
    'Production configuration lives in Kustomize, with first-party images pinned by digest. The repository provides make gitops-check to validate the desired state. Argo CD reconciles reviewed Git changes, and the documented rollback path is a Git revert. These are solo projects, with automated review tools and my own review.',
  links: [
    {
      label: 'GitOps delivery and rollback procedure',
      href: repositorySource('cyber-stack/README.md'),
    },
    {
      label: 'Repository validation targets',
      href: repositorySource('Makefile'),
    },
  ],
} as const;

export const about = {
  title: 'About Rafael',
  description:
    'Rafael Cardoso, Senior Software Engineer in Portland, Maine. Java and Oracle ERP Cloud integrations at Synchro and independent Scala ingestion and Go search projects.',
  eyebrow: professionalHeadline.toUpperCase(),
  introduction:
    'I’m a senior software engineer in Portland, Maine, with 15+ years in software and enterprise integrations. At Synchro, my work covered fiscal requirements, Oracle ERP integrations, data reconciliation, release validation, and production recovery. Since September 2024, I’ve built backend services, event ingestion, and operational search independently through RCLabs.',
  primaryCta: hiring.resume,
  secondaryCta: { label: 'GitHub profile', href: author.profile },
  scope: {
    title: 'What I work on',
    domains: [
      {
        title: 'Distributed systems',
        description:
          'Message pipelines, offset-based deduplication, and recovery after interrupted processing. Octopus is my current independent implementation.',
        tags: ['Scala 3', 'Cats Effect', 'FS2', 'Redpanda', 'PostgreSQL'],
      },
      {
        title: 'Enterprise integration',
        description:
          'Fiscal integrations between Oracle ERP Cloud, electronic invoicing, and tax systems, including data validation and recovery from failed transactions.',
        tags: [
          'Java',
          'Spring Boot',
          'Apache Camel',
          'Oracle ERP Cloud',
          'PL/SQL',
          'XSLT',
        ],
      },
      {
        title: 'Retrieval',
        description:
          'Ingestion, embedding workers, and keyword and vector search. Atheros Search exposes processing state and the records behind each result.',
        tags: ['Go', 'PostgreSQL', 'pgvector', 'SolidJS'],
      },
      {
        title: 'Security and observability',
        description:
          'Service authentication, role separation, deployment threat models, image digest pinning, and telemetry for diagnosing production failures.',
        tags: ['Rust', 'WireGuard', 'Kubernetes', 'Kustomize', 'Argo CD'],
      },
    ],
  },
  contact: {
    title: 'What I am looking for',
    summary:
      'A role where I can own backend systems, contribute to architecture, and work closely with an engineering team.',
    signals: [
      [
        'Role scope',
        'Senior software engineering roles in backend systems, enterprise integration, or data pipelines.',
      ],
      [
        'Best environment',
        'Teams that give engineers responsibility for design, delivery, and production support.',
      ],
      [
        'Useful conversations',
        'Backend and data-platform architecture, team structure, retrieval systems, and distributed-systems security.',
      ],
    ],
  },
  evidenceTitle: 'About the examples',
  evidence:
    'The source and tests are from my independent projects. Browser samples use synthetic records. Synchro workload comes from my resume and describes the historical employer system. None establishes customer adoption or service-level commitments.',
  threatModel: 'Repository threat model',
  threatModelHref:
    'https://github.com/zlovtnik/ssl-proxy/blob/main/docs/threat-model.md',
} as const;

// The two load-bearing caveats, defined once so the product pages and the
// homepage reference entries can never drift apart.
export const searchCaveat =
  'Sensor placement, configured channel coverage, observation time, and MAC randomization limit what can be seen. An observed Wi-Fi identifier does not confirm a current connection or physical device identity.';
export const migratorCaveat =
  'SQL-file snapshots preserve source files and checksums. They do not back up database data.';
export const vpnCaveat =
  'Traffic categories are heuristics. Routing, inspection, and policy outcomes depend on deployment configuration. This synthetic sample establishes no VPN connection and sends no traffic.';
export const octopusCaveat =
  'Delivery can repeat. Octopus records progress and uses durable deduplication to handle replay. Records outside the configured streams are not covered.';

export const octopusMetrics = {
  status: {
    ssr: 'Production metrics',
    loading: 'Connecting to production',
    live: 'Live production data',
    warmup: 'Production connected · warming up',
    delayed: 'Live metrics delayed',
    historical: 'Latest recorded production data',
    unavailable: 'Waiting for production data',
  },
  pipelineTitle: 'Pipeline now',
  snapshotTitle: 'Latest snapshot',
  recorded24hTitle: 'Recorded 24-hour window',
  recorded7dTitle: 'Recorded 7-day window',
  current24hTitle: 'Last 24 hours',
  current7dTitle: 'Last 7 days',
  recordedMessage:
    'Recorded totals and hourly history remain available while live collection starts or recovers.',
  label: 'PIPELINE OBSERVABILITY',
  title: 'Backlog and stalled work',
  summary:
    'Check processing, queued work, and recorded production history to see where investigation should begin.',
  noScript:
    'Enable JavaScript to load current metrics. No saved measurements are shown.',
  empty: {
    title: 'Waiting for a production reading',
    loadingTitle: 'Loading production metrics',
    description:
      'A fresh reading is needed to show processing and backlog. The public feed cannot currently confirm pipeline activity. This does not establish whether processing has stopped.',
    loadingDescription:
      'Fetching the latest production reading. Metrics appear once the response is validated.',
    retry: 'This page retries automatically while it is open.',
    link: 'Explore the receive, process, and record workflow',
    href: '#workflow-title',
  },
  warmup:
    'Production is connected. Processing and backlog readings appear once the five-minute rate window and collection are ready.',
  missingHistory: 'Historical peaks have not been recorded in this snapshot.',
  missingCheck: 'No successful check recorded',
  missingThroughput:
    'Lifetime totals and hourly history have not been published in this reading.',
  methodTitle: 'What these numbers mean',
  method: [
    'Pipeline readings refresh every 30 seconds. When live collection is delayed, the latest recorded totals and hourly history remain visible with their original measurement times. The page retries automatically and keeps a validated public snapshot in this browser for later visits. No example values or build-time snapshots are used.',
    'The processing rate covers successfully committed broker deliveries at the responding coordinator, averaged over five minutes, including replays and parked records. Pending ledger rows and broker backlog are separate measurements. Live gauges appear once the rate window and collection are ready.',
    'Historical peaks count rows in the production ingestion ledger across all paths and outcomes. They are not unique business events or a capacity benchmark. Days use UTC. Weeks run Monday to Sunday. Current periods are counted so far. History is refreshed separately, with its own measurement time.',
    'Lifetime totals and hourly throughput windows count rows in the same ingestion ledger. The last-24-hours window holds 24 measured hourly totals and the last-7-days window holds 168. A measured hour may honestly be zero. A window that was never computed stays unavailable instead of showing zeros.',
  ],
} as const;

export const octopusContact = {
  eyebrow: 'CONTACT',
  headline: ['Discuss the', 'engineering decisions.'],
  supporting:
    'Hiring for backend or data-pipeline work? I can walk through replay, fencing, and recovery in Octopus.',
  link: 'Email Rafael',
} as const;

export const home = {
  // Google rewrites and truncates titles; this is an editorial target, not a
  // ranking rule. The homepage shares one title and description with Layout.
  title: 'Backend Engineering, Event Ingestion & Search',
  description:
    'Backend systems and enterprise integrations by Rafael Cardoso. Explore durable Scala ingestion, Go hybrid search, and PostgreSQL migration tooling.',
  headline: ['Backend systems for', 'data ingestion, recovery, and search'],
  subheadline:
    'I’m Rafael Cardoso, a senior software engineer in Portland, Maine. I build backend services and enterprise integrations. These independent projects handle replayed events, interrupted jobs, and search results where a reviewer can inspect which records matched and why.',
  primaryCta: {
    label: 'Explore the work',
    href: '#selected-work',
  },
  secondaryCta: hiring.resume,
  supporting:
    'Open to senior backend, integration, and data-pipeline roles. Remote or hybrid, U.S.-authorized, no sponsorship required.',
  eyebrow: 'RAFAEL CARDOSO / RCLABS',
  reviewTitle: 'Start here',
  navigationContact: 'Contact',
  experience: portfolio.experience,
  workEyebrow: 'Independent projects',
  workSummary:
    'Search, ingestion, network observations, and SQL change review. Implementation details and evidence live with each project.',
  projects: [
    {
      id: 'octopus',
      title: 'Octopus',
      category: 'Durable ingestion',
      stack: 'Scala / Redpanda / PostgreSQL',
      summary:
        'I built a Scala coordinator that persists event and job state before committing broker offsets. Deduplication handles replay, and fenced leases let it reclaim interrupted work and reject stale completion.',
      caveat:
        'Delivery may repeat. Saved progress and deduplication support replay across configured streams.',
      link: { label: 'Workflow and live readings', href: '/octopus/' },
    },
    {
      id: 'search',
      title: 'Atheros Search',
      category: 'Retrieval & investigation',
      stack: 'Go / PostgreSQL / pgvector',
      summary:
        'I built a Go service that combines keyword and vector search. The workbench shows source records and ranking evidence. Leased embedding jobs can recover after interruption.',
      caveat:
        'Synthetic public sample. An observation does not confirm a current connection or device identity. Identity suggestions are review candidates.',
      link: { label: 'Search documentation', href: '/atheros-search/' },
    },
    {
      id: 'migrator',
      title: 'Schema Migrator',
      category: 'SQL change review',
      stack: 'Scala / Cats Effect',
      summary:
        'Ordered SQL-file validation, shortened dry-run previews, and selected catalog checks. Column definitions and nullability are outside drift comparison scope.',
      caveat: `${migratorCaveat} The sample executes no SQL.`,
      link: { label: 'Migration walkthrough', href: '/schema-migrator/' },
    },
    {
      id: 'vpn',
      title: 'RCLabs VPN / Proxy',
      category: 'Network observations',
      stack: 'Rust / WireGuard',
      summary:
        'WireGuard ingress, transparent proxy handling, classification, and audit-event publishing.',
      caveat:
        'Classification is a review aid. It does not prove intent, prevent a connection, or cover traffic outside the configured path.',
      link: { label: 'Proxy walkthrough', href: '/vpn-proxy/' },
    },
  ],
  sampleNote:
    'Public Search, Migrator, and VPN / Proxy samples use synthetic data. Octopus operational readings come from its runtime feed.',
  evidence: {
    eyebrow: 'Source & tests',
    title: 'Source, tests, and known gaps',
    summary:
      'Follow each project’s failure handling into its implementation and regression tests.',
    link: 'View source on GitHub',
  },
  guidesEyebrow: 'Worked examples',
  guidesTitle: 'Technical guides',
  guidesLink: 'All guides',
  guides: [
    {
      slug: 'postgresql-migration-dry-run',
      title: 'PostgreSQL migration dry runs',
      summary:
        'Discovery, validation, and an offline preview before execution.',
    },
    {
      slug: 'postgresql-schema-drift',
      title: 'PostgreSQL schema drift',
      summary:
        'Expected definitions, observed catalog state, and review boundaries.',
    },
    {
      slug: 'migration-checksum-mismatch',
      title: 'Migration checksum mismatches',
      summary: 'File integrity, snapshot changes, and what they establish.',
    },
    {
      slug: 'rogue-access-point-investigation',
      title: 'Suspected rogue access points',
      summary:
        'Wireless observations with site and authorized-network context.',
    },
    {
      slug: 'wifi-deauthentication-investigation',
      title: 'Wi-Fi deauthentication indicators',
      summary: 'Time windows, capture scope, and corroborating evidence.',
    },
    {
      slug: 'hybrid-search-network-observations',
      title: 'Hybrid search for observations',
      summary: 'Term, vector, and fused retrieval on synthetic records.',
    },
  ],
  contact: {
    eyebrow: 'Contact',
    title: 'Hiring for backend engineering?',
    summary:
      'Email me about a senior backend, integration, or data-pipeline role.',
    projects: { label: 'Contact Rafael', href: '/contact/' },
  },
  reviewPath: [
    {
      title: 'Professional experience',
      text: 'Roles, contributions, and historical workload.',
      href: '#experience',
    },
    {
      title: 'Selected engineering work',
      text: 'Independent projects and technical walkthroughs.',
      href: '#selected-work',
    },
    {
      title: 'Source and tests',
      text: 'Code, test evidence, and verification gaps.',
      href: '#technical-evidence',
    },
  ],
  productsEyebrow: 'PROJECT DOCUMENTATION',
  productsTitle: 'The projects',
  productsSummary:
    'Search, ingestion, network observations, and SQL change review, with implementation details and synthetic examples.',
  relationship:
    'Atheros Search brings retrieval, ingestion visibility, and source readiness into one authenticated console. Octopus coordinates durable ingestion. The proxy and Atheros Sensor, a monitor-mode wireless capture service, produce observations. Schema Migrator is companion tooling. Public samples run independently in your browser.',
  faqTitle: 'Before you start',
  faq: [
    {
      question: 'Do the samples use real data or change anything?',
      answer:
        'The Search, Migrator, and VPN / Proxy samples use synthetic records in your browser. They execute no SQL, open no VPN connection, and change no production systems. Octopus separately loads public production metrics.',
    },
    {
      question: 'How do the projects fit together?',
      answer:
        'The proxy records network observations. Atheros Sensor captures wireless observations on configured Wi-Fi channels. Octopus records and processes them, and Atheros Search indexes and retrieves them. Schema Migrator is companion tooling for reviewing SQL changes.',
    },
    {
      question: 'What roles am I looking for?',
      answer:
        'Senior backend, enterprise integration, and data-pipeline roles where I can own design, delivery, and production support. Contact me with the role and team context.',
    },
  ],
} as const;

export const catalogue = {
  title: 'Projects',
  description:
    'Explore independent engineering projects for event ingestion, hybrid search, network observations, and SQL change review.',
  headline: ['Projects and', 'documentation'],
  summary:
    'Atheros Search retrieves observations produced by the proxy and sensor and processed by Octopus. Schema Migrator is separate tooling for SQL change review.',
  comparisonTitle: 'Responsibilities',
  comparisonSummary: 'Each component has a different input and output.',
} as const;

export const searchComponents = [
  { label: 'Proxy observation source: technical details', href: '/vpn-proxy/' },
  {
    label: 'Octopus ingestion: technical details and measured activity',
    href: '/octopus/',
  },
  {
    label: 'Schema Migrator: companion change-review tooling',
    href: '/schema-migrator/',
  },
] as const;

// Captured SQL inputs and CLI output used by the migration dry-run guide.
const migrationExamples = {
  ordering: {
    tree: `sql/
  extensions/
  schemas/
  types/
  tables/001_observations.sql
  indexes/002_observed_at.sql
  functions/
  views/
  cron/
  materialized_views/`,
    files: [
      {
        path: 'tables/001_observations.sql',
        sql: `-- object: observations
-- folder: tables
-- depends_on: -
create table if not exists observations (
  id bigint primary key,
  source text not null,
  observed_at timestamptz not null
);`,
      },
      {
        path: 'indexes/002_observed_at.sql',
        sql: `-- object: observations observed_at index
-- folder: indexes
-- depends_on: observations
create index if not exists observations_observed_at_idx
  on observations (observed_at desc);`,
      },
    ],
  },
  preview: {
    runs: [
      {
        command: 'sbt "run --db-kind postgres --sql-dir ./sql list"',
        output: `tables/001_observations.sql
indexes/002_observed_at.sql`,
        note: 'Discovery prints files in apply order. No database is contacted.',
      },
      {
        command: 'sbt "run --db-kind postgres --sql-dir ./sql validate"',
        output: `warning: tables/001_observations.sql: expected 'CREATE TABLE IF NOT EXISTS' for idempotency`,
        note: 'Findings are reported per file with the path that produced them. A clean directory prints nothing and exits 0, and warnings do not fail the run.',
      },
      {
        command: 'sbt "run --db-kind postgres --sql-dir ./sql validate"',
        output: `error: tables/002_broken.sql: SQL parsing check failed (unterminated single-quoted string)`,
        note: 'An invalid file is reported with its path and the run exits non-zero, so a pipeline can stop before any execution is attempted.',
      },
      {
        command: 'sbt "run --db-kind postgres --sql-dir ./sql --dry-run apply"',
        output: `tables/001_observations.sql                      -- object: observations -- folder: tables -- depends_on: - create table if not exists observations ( id bigint primary ...
indexes/002_observed_at.sql                      -- object: observations observed_at index -- folder: indexes -- depends_on: observations create index if not exists obs...`,
        note: 'The preview prints each path with its SQL compacted to one line and cut after 120 characters. The current CLI shows ordered, shortened previews, not a complete executable deployment script.',
      },
    ],
  },
} as const;

// Shared section structure, with each product's story kept in its own model.
const workflowSection = { label: 'HOW IT WORKS' } as const;
const audienceSection = {
  label: 'USING THE SOFTWARE',
} as const;
const evidenceSection = {
  label: 'IMPLEMENTATION',
  title: 'Implementation details',
} as const;
const glossarySection = {
  label: 'GLOSSARY',
  title: 'Terms',
} as const;

export const products = [
  {
    id: 'search',
    name: 'Atheros Search',
    path: '/atheros-search/',
    label: 'INGESTION / INDEXING / EVIDENCE RETRIEVAL',
    homeTitle: 'Atheros Search',
    headline: ['Search over', 'source observations.'],
    cardSummary:
      'Go service for keyword and vector search with PostgreSQL and pgvector, source records, and ranking explanations.',
    summary:
      'Atheros Search combines keyword and vector retrieval over configured proxy and wireless observations. In the authenticated workbench, inspect source records, ranking evidence, ingestion state, and embedding jobs. When semantic retrieval is unavailable, the service can return a labeled keyword fallback.',
    hostedConsoleNotice: {
      text: 'The hosted console is temporarily unavailable:',
      link: { label: 'search.rclabs.uk', href: 'https://search.rclabs.uk/' },
      followup: '. The synthetic sample below remains available.',
    },
    problem:
      'RAG builders and operators who need retrievable evidence, visible processing gaps, and source context for human review.',
    primaryCta: { label: 'Explore a sample site review', href: '#demo' },
    secondaryCta: {
      label: 'Source and regression tests',
      href: '/about/#case-search',
    },
    sections: {
      workflow: {
        ...workflowSection,
        title: 'Ingestion and retrieval',
        note: 'The authenticated workbench includes retrieval, sources, ingestion, and processing. This synthetic sample follows a site, an indicator, and its observations. The current production console does not yet show this complete site overview end to end. Generated answers and new connectors remain future work.',
      },
      value: {
        ...audienceSection,
        title: 'Working with Search',
      },
      evidence: {
        ...evidenceSection,
        caveatLabel: 'COVERAGE AND IDENTITY',
        footnote:
          'The sensor listens on configured channels and publishes audit records to the configured backend. Deployment requires monitor-mode Wi-Fi hardware. Audit fields and retention depend on deployment. No retention duration is promised here.',
      },
      glossary: glossarySection,
    },
    audiences: [
      {
        id: 'technical',
        title: 'Retrieval interfaces',
        proposition: 'Retrieve records and their source context.',
        points: [
          'Search dense, sparse, or hybrid records through existing HTTP and gRPC interfaces, with supported filters and ranking explanations.',
          'Distinguish available lexical evidence from semantic coverage. Missing vectors, failed embedding jobs, and unknown measurements do not establish indexing readiness.',
        ],
      },
      {
        id: 'buyers',
        title: 'Ingestion and indexing state',
        proposition: 'Check ingestion and indexing failures.',
        points: [
          'Inspect stages, backlog, failures, workers, and measurement freshness alongside retrieval, using the existing login and role permissions.',
          'Separate indexed proxy evidence from operator-only live aggregate telemetry. Operational readings are global unless explicitly scoped. Missing data stays unknown.',
        ],
      },
    ],
    workflow: [
      {
        step: 'Observe and ingest',
        input: 'Configured proxy and wireless observations',
        processing:
          'Publish events. Octopus records evidence and deduplicates repeated delivery',
        output: 'Durable ingestion evidence within configured source coverage',
      },
      {
        step: 'Prepare and index',
        input: 'Ingested observations and maintained projections',
        processing:
          'Octopus prepares documents and jobs. Fenced Search workers create embeddings',
        output: 'Searchable documents and available vector coverage',
      },
      {
        step: 'Retrieve and inspect',
        input: 'A query and supported evidence filters',
        processing:
          'Rank term and vector matches. Inspect supporting records and explanations',
        output: 'Evidence for human review or a downstream RAG workflow',
      },
    ],
    caveat: searchCaveat,
    highlights: [
      [
        'Follow ingestion',
        'Trace configured sources, processing, and freshness.',
      ],
      [
        'Inspect indexing readiness',
        'Separate lexical evidence from available semantic coverage.',
      ],
      [
        'Retrieve supporting evidence',
        'Review ranked records and explanations. Answer generation is deferred.',
      ],
    ],
    features: [
      [
        'Listen on configured Wi-Fi channels',
        'Atheros Sensor uses monitor-mode capture. It listens on configured channels rather than joining access points, then publishes audit records to the configured backend.',
      ],
      [
        'Review configured wireless indicators',
        'Sensor heuristics can flag suspected rogue access points, deauthentication floods, signal anomalies, attack sequences, and PMF-related patterns for analyst review.',
      ],
      [
        'Inspect supporting observations',
        'Review wireless audit records with site, sensor, channel, and observed-time context. Retention details depend on deployment.',
      ],
      [
        'Treat identifiers carefully',
        'Inventory shows observed Wi-Fi identifiers. MAC randomization and incomplete sensor coverage mean identifiers are not a count of confirmed physical devices.',
      ],
      [
        'See processing progress',
        'The ingestion and sources views expose allowlisted processing and coverage measurements. Inspect embedding jobs, worker heartbeats, failures, and timestamps without treating unavailable data as zero.',
      ],
      [
        'Recover interrupted embedding jobs',
        'Workers check the job lease and document revision before writing the vector and completing the job in one transaction.',
      ],
    ],
    glossary: [
      [
        'Dense search',
        'Finds records with similar meaning using numerical representations called embeddings.',
      ],
      ['Sparse search', 'Finds records by matching terms.'],
      ['Hybrid search', 'Combines meaning and term matches to rank results.'],
      [
        'Wireless indicator',
        'A configured sensor heuristic that points to a wireless pattern for an analyst to review. It does not prove a threat.',
      ],
      [
        'Observed Wi-Fi identifier',
        'An identifier seen in captured wireless traffic. It may not map one-to-one to a physical device.',
      ],
      [
        'Observed relationship',
        'A link supported by recorded observations. It does not prove a current connection or confirmed identity.',
      ],
      [
        'ETL',
        'Extract, transform, load: the processing steps that prepare data for use.',
      ],
    ],
  },
  {
    id: 'migrator',
    name: 'Schema Migrator',
    path: '/schema-migrator/',
    homeTitle: 'Schema Migrator',
    label: 'DATABASE CHANGE REVIEW',
    headline: ['Review SQL changes', 'before you run them.'],
    cardSummary:
      'Scala tooling for SQL-file validation, execution planning, catalog drift checks, and run history.',
    summary:
      'Discover ordered SQL and validate it offline. Dry-run output is shortened. Review the full source files alongside it. Catalog drift checks compare selected object definitions and table presence, but do not compare column definitions or nullability.',
    hostedConsoleNotice: {
      text: 'The hosted console is temporarily unavailable:',
      link: {
        label: 'migrator.rclabs.uk',
        href: 'https://migrator.rclabs.uk/',
      },
      followup: '. The synthetic sample below remains available.',
    },
    problem:
      'Platform and database engineers reviewing SQL execution order, target drift, and evidence of previous changes.',
    primaryCta: { label: 'Explore a sample migration review', href: '#demo' },
    secondaryCta: {
      label: 'Source and regression tests',
      href: '/about/#case-migrator',
    },
    sections: {
      workflow: {
        ...workflowSection,
        title: 'Validation, planning, and run history',
        note: 'File validation and planning run offline. Catalog checks and execution need a configured target. The public demonstration executes no SQL.',
      },
      value: {
        ...audienceSection,
        title: 'Working with Migrator',
      },
      evidence: {
        ...evidenceSection,
        caveatLabel: 'SQL-FILE SNAPSHOTS',
        footnote:
          'The sample review records are synthetic. It connects to no target and executes no SQL.',
      },
      glossary: glossarySection,
    },
    audiences: [
      {
        id: 'technical',
        title: 'SQL planning and target state',
        proposition: 'Check SQL order and target state.',
        points: [
          'Discover ordered SQL and run offline validation before reviewing a dry-run plan.',
          'Inspect PostgreSQL catalog drift, SQL-file checksums, and recorded runs through the CLI and operator interfaces.',
        ],
      },
      {
        id: 'buyers',
        title: 'Run records and configuration',
        proposition: 'Keep run records and target configuration.',
        points: [
          'Use stored run and audit records to support change reviews and operational handoffs.',
          'Keep target configuration and encrypted credentials in one service, with connection checks and guarded execution.',
        ],
      },
    ],
    workflow: [
      {
        step: 'Validate',
        input: 'SQL files and ordering configuration',
        processing: 'Discover files and validate inputs offline',
        output: 'Ordered files and validation findings',
      },
      {
        step: 'Plan',
        input: 'Validated files and target configuration',
        processing: 'Generate a dry-run plan',
        output: 'Proposed execution order for review',
      },
      {
        step: 'Review the record',
        input: 'A completed run and saved SQL files',
        processing: 'Retrieve execution evidence and compare checksums',
        output: 'Run history and file changes',
      },
    ],
    caveat: migratorCaveat,
    highlights: [
      [
        'Read the source',
        'Inspect SQL files and their explicit execution order.',
      ],
      ['Review the plan', 'Check inputs offline and examine the dry-run plan.'],
      [
        'Keep the evidence',
        'Inspect audit records and compare SQL-file snapshots.',
      ],
    ],
    features: [
      [
        'Inspect supported catalog drift',
        'Compare functions, procedures, triggers, views, materialized views and indexes, plus table presence. Column definitions and nullability are outside the comparison scope.',
      ],
      [
        'Compare SQL files',
        'Capture SQL-file snapshots and compare their checksums. These snapshots preserve source files. They are not database backups.',
      ],
      [
        'Manage your targets',
        'Keep target configuration in one place, check connections, and store target credentials encrypted. PostgreSQL is the primary target story.',
      ],
      [
        'Record migration runs',
        'Discover files in order, validate offline, review dry-run plans, and inspect guarded migration runs and audit records. Review before applying to a real target.',
      ],
    ],
    glossary: [
      [
        'SQL',
        'Structured Query Language: the language used to define and query database structures.',
      ],
      [
        'Schema',
        'The structure of a database, including tables, columns, and related objects.',
      ],
      ['Dry-run', 'A plan of proposed work without applying the changes.'],
      [
        'Drift',
        'A difference between expected definitions and the database structure.',
      ],
      [
        'SQL-file snapshot',
        'A saved set of SQL source files and checksums. It does not back up database data.',
      ],
      [
        'Checksum',
        'A value calculated from a file to detect changes to its contents.',
      ],
    ],
  },
  {
    id: 'vpn',
    name: 'RCLabs VPN / Proxy',
    path: '/vpn-proxy/',
    homeTitle: 'RCLabs VPN / Proxy',
    label: 'ATHEROS SEARCH COMPONENT / OBSERVATION SOURCE',
    headline: ['WireGuard ingress.', 'Traffic classification.'],
    cardSummary:
      'Rust proxy for WireGuard ingress, configured traffic handling, and audit-event publishing.',
    summary:
      'The Rust proxy receives WireGuard traffic, applies configured connection policies, and publishes classified observations for Atheros Search. Coverage depends on the configured routing and available connection metadata.',
    problem:
      'Network and platform teams operating WireGuard ingress, transparent proxy policies, and traffic audit pipelines.',
    primaryCta: { label: 'Explore a sample traffic flow', href: '#demo' },
    secondaryCta: { label: 'Explore Atheros Search', href: '/atheros-search/' },
    sections: {
      workflow: {
        ...workflowSection,
        title: 'Ingress, handling, and audit records',
        note: 'The sample follows one configured traffic path and its recorded decision. It does not establish a tunnel.',
      },
      value: {
        ...audienceSection,
        title: 'Operating the proxy',
      },
      evidence: {
        ...evidenceSection,
        caveatLabel: 'CONFIGURATION / COVERAGE',
        footnote:
          'Sample flows and decisions are illustrative fixtures. No credentials, network connection, or live policy changes are involved.',
      },
      glossary: glossarySection,
    },
    audiences: [
      {
        id: 'technical',
        title: 'Traffic handling and classification',
        proposition: 'Inspect traffic handling and classification.',
        points: [
          'Review WireGuard ingress and transparent proxy handling as distinct stages of the traffic path.',
          'Inspect coarse traffic categories and the configured reasons behind connection handling.',
        ],
      },
      {
        id: 'buyers',
        title: 'Peers and audit publishing',
        proposition: 'Configure peers and audit publishing.',
        points: [
          'Evaluate the proxy, administrative readiness surfaces, and the separate staged WireGuard key rotator.',
          'Plan for audit publishing through Redpanda and backend processing through Octopus. Persistence is owned by the backend.',
        ],
      },
    ],
    workflow: [
      {
        step: 'Enter',
        input: 'A configured WireGuard peer and traffic',
        processing: 'Receive traffic through WireGuard ingress',
        output: 'Traffic available to the configured proxy path',
      },
      {
        step: 'Handle',
        input: 'Destination and available connection metadata',
        processing: 'Classify the flow and apply configured handling',
        output: 'A connection decision with a recorded reason',
      },
      {
        step: 'Inspect',
        input: 'Proxy observations and audit events',
        processing: 'Publish evidence to the configured backend',
        output: 'Records for operational review',
      },
    ],
    caveat: vpnCaveat,
    highlights: [
      ['WireGuard ingress', 'Receive traffic from configured peers.'],
      ['Transparent handling', 'Inspect categories and configured decisions.'],
      ['Audit publishing', 'Follow observations into the backend pipeline.'],
    ],
    features: [
      [
        'Receive WireGuard traffic',
        'The Rust proxy owns WireGuard ingress and tunnel transport. Peer setup and network routing are deployment prerequisites.',
      ],
      [
        'Classify destinations',
        'Hostname and port heuristics group traffic as advertising/tracking, analytics, CDN, essential API, authentication, or unknown. A category is not a security verdict.',
      ],
      [
        'Inspect configured handling',
        'The transparent proxy supports policy-driven connection handling, including blocking and bypass paths. The active configuration determines the outcome.',
      ],
      [
        'Publish audit evidence',
        'The proxy publishes observations to the configured Redpanda pipeline. Octopus owns durable ingestion and maintained PostgreSQL projections.',
      ],
      [
        'Operate peer keys separately',
        'The WireGuard key rotator supports staged server and peer key rotation as a separate operational component.',
      ],
    ],
    glossary: [
      [
        'WireGuard',
        'A VPN protocol used here as a traffic ingress path for configured peers.',
      ],
      [
        'Transparent proxy',
        'A proxy that receives traffic through configured network routing rather than an application-specific proxy setting.',
      ],
      [
        'Traffic category',
        'A coarse label inferred from destination metadata. It does not prove whether traffic is safe or malicious.',
      ],
      [
        'Policy decision',
        'The connection handling selected by the configured rules, with its recorded reason.',
      ],
      [
        'Audit publishing',
        'Sending observations to a backend pipeline for processing and later review.',
      ],
    ],
  },
  {
    id: 'octopus',
    name: 'Octopus',
    path: '/octopus/',
    homeTitle: 'Octopus',
    label: 'INDEPENDENT PROJECT / INGESTION COORDINATOR',
    headline: ['Durable event', 'ingestion.'],
    cardSummary:
      'Scala coordinator for durable Redpanda ingestion, PostgreSQL deduplication, and recovery with fenced work leases.',
    summary:
      'Octopus coordinates event ingestion, document preparation, and PostgreSQL projections. It records durable state before advancing consumer offsets. Deduplication handles repeated deliveries, stable dispatch keys identify repeat sends, and fenced leases reject stale completion.',
    problem:
      'For platform and data teams running event pipelines that need to recover from failures and account for repeated delivery.',
    primaryCta: {
      label: 'View live metrics',
      href: '#operational-evidence',
    },
    secondaryCta: {
      label: 'Explore Atheros Search',
      href: '/atheros-search/',
    },
    sections: {
      workflow: {
        ...workflowSection,
        title: 'Events, jobs, and outcomes',
        note: 'Each stage records the state needed by the next.',
      },
      value: {
        ...audienceSection,
        label: 'DEBUGGING',
        title: 'How I debug it',
        note: 'Start with the consumer group, topic, partition, and offset. Follow persisted state and compare it with backlog and measurement freshness.',
      },
      evidence: {
        ...evidenceSection,
        label: 'IMPLEMENTATION',
        title: 'Persistence and recovery',
        note: 'Built in Scala with Cats Effect and FS2, using Redpanda streams and PostgreSQL for persistent state.',
        caveatLabel: 'DELIVERY AND RECOVERY',
        footnote:
          'Consumer offsets, job state, and load results give operators a place to start when work stalls.',
      },
      glossary: {
        label: 'GLOSSARY',
        title: 'Terms',
      },
    },
    audiences: [
      {
        id: 'technical',
        title: 'Trace delivery and recovery',
        proposition: 'Trace source records and recovery state.',
        points: [
          'Start incident triage at the source: find the consumer group, topic, partition, and offset behind an ingestion record.',
          'Inspect durable deduplication and committed offsets to understand replay after a restart.',
          'Follow job claims, batches, and database load results through the Scala, Cats Effect, and FS2 coordinator.',
        ],
      },
      {
        id: 'buyers',
        title: 'Check backlog and freshness',
        proposition: 'Check processing and backlog.',
        points: [
          'Check processing rate and queued records to identify a growing backlog.',
          'See whether intake is accepting work or paused to let the backlog drain.',
          'Compare hourly throughput and recorded peaks, with timestamps that distinguish fresh readings from delayed data.',
        ],
      },
    ],
    workflow: [
      {
        step: 'Receive events',
        stageLabel: 'Receive',
        input: 'Events and requests from configured streams',
        processing: 'Read from saved offsets and check for repeated delivery',
        output: 'Recorded events ready for processing',
      },
      {
        step: 'Coordinate jobs',
        stageLabel: 'Process',
        input: 'Queued records and jobs',
        processing: 'Claim work, form batches, and dispatch database loads',
        output: 'Tracked jobs with load results',
      },
      {
        step: 'Record outcomes',
        stageLabel: 'Record',
        input: 'Processing results and source offsets',
        processing: 'Save ingestion history and update configured data views',
        output: 'A persistent record operators can inspect',
      },
    ],
    caveat: octopusCaveat,
    highlights: [
      ['Receive', 'Read events from configured streams.'],
      ['Coordinate', 'Claim jobs, build batches, and track loads.'],
      ['Recover', 'Resume from saved progress and handle replay.'],
    ],
    features: [
      [
        'Source coordinates',
        'Start incident triage with the consumer group, topic, partition, and offset stored on each ingestion record. Replayed records keep their original first-seen time so you can trace the original delivery.',
      ],
      [
        'Committed offsets and deduplication',
        'Recover after a restart using committed consumer offsets and durable deduplication for repeated delivery. New groups begin at the earliest records still retained.',
      ],
      [
        'Leases and pending work',
        'Time-limited claims coordinate workers competing for queued work. Inspect stored jobs, batches, and outgoing messages to see the state of each load when processing stalls.',
      ],
      [
        'PostgreSQL projections',
        'Octopus updates PostgreSQL data views and derives alerts. Atheros Search runs the separate workers that create embeddings.',
      ],
    ],
    glossary: [
      [
        'Ingest ledger',
        'A stored record of consumed events and their outcomes, identified by consumer group, topic, partition, and offset.',
      ],
      ['Lease', 'A time-bounded claim on work used to coordinate processing.'],
      ['Outbox', 'Durable records of messages waiting for dispatch.'],
      [
        'At-least-once',
        'A delivery model in which records may be delivered again. Durable deduplication handles repeated work.',
      ],
      [
        'Peak day / week',
        'The highest historical ledger-row count in a UTC calendar day or Monday-to-Sunday ISO week, including the current period so far.',
      ],
    ],
  },
] as const;

export type Product = (typeof products)[number];
export type ProductId = Product['id'];
export function getProduct(id: ProductId): Product {
  return products.find((product) => product.id === id)!;
}

// Octopus publishes measured evidence; it has no synthetic demo.
export const sampleProducts = products.filter(
  (product) => product.id !== 'octopus',
);

export const contact = {
  eyebrow: 'CONTACT',
  headline: ['Hiring for', 'backend engineering?'],
  supporting:
    'Email me about a senior backend, integration, or data-pipeline role. I can walk through the implementation and tradeoffs behind these projects.',
  cta: 'Contact Rafael',
  // Short form for a mailto link that already sits under the headline, so the
  // same words never appear twice in one block.
  link: 'Email Rafael',
  emailHint: 'Opens your email app, or email',
  nextStep: 'Start by email. We can arrange a technical call together.',
} as const;

export const allProducts = products.map((product) => product.name).join(', ');

export const contactOptions = [
  {
    id: 'search',
    label: 'Atheros Search',
    subject: 'Atheros Search',
    text: 'Keyword and vector retrieval, embedding jobs, and source observations.',
  },
  {
    id: 'migrator',
    label: 'Schema Migrator',
    subject: 'Schema Migrator',
    text: 'Review SQL files, dry-run plans, and run records.',
  },
  {
    id: 'vpn',
    label: 'RCLabs VPN / Proxy',
    subject: 'RCLabs VPN / Proxy',
    text: 'WireGuard peers, transparent proxy policies, and audit publishing.',
  },
  {
    id: 'octopus',
    label: 'Octopus',
    subject: 'Octopus',
    text: 'Ingestion, deduplication, work leases, backlog, and recovery.',
  },
  {
    id: 'all',
    label: 'System walkthrough',
    subject: allProducts,
    text: 'How the ingestion and search components fit together, plus the separate SQL tooling.',
  },
] as const;

export function discussionLink(product: string) {
  const subject = `Engineering discussion: ${product}`;
  const body = `Hello Rafael,\n\nI'd like to discuss the engineering behind ${product}.\n\nRole or project context:\n\nQuestions:\n\nThank you.`;
  return `mailto:${email}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
}

export const notFound = {
  title: 'Page not found',
  description:
    'This page is no longer available. Explore RCLabs projects and technical guides.',
  eyebrow: '404 / PAGE NOT FOUND',
  heading: 'This page is not available.',
  summary: 'The address may have changed, or the page may have been retired.',
  productsLabel: 'Explore the projects',
  guidesLabel: 'Read the technical guides',
} as const;

export interface GuideSection {
  id: string;
  title: string;
  paragraphs: readonly string[];
  points?: readonly string[];
  examples?: readonly { label: string; code: string; note: string }[];
  table?: {
    caption: string;
    headers: readonly string[];
    rows: readonly (readonly string[])[];
  };
}

export interface Guide {
  slug: string;
  title: string;
  description: string;
  productId: ProductId;
  eyebrow: string;
  introduction: string;
  caveat: string;
  sections: readonly GuideSection[];
  sources: readonly { label: string; href: string; note: string }[];
  related: readonly string[];
}

export const guideIndex = {
  title: 'Technical guides',
  listLabel: 'All guides',
  description:
    'Practical guides to PostgreSQL migration dry runs, schema drift, file checksums, wireless indicators, and hybrid search, with worked examples and limits.',
  summary:
    'Worked examples for SQL migrations, wireless investigations, and hybrid search.',
  eyebrow: 'TECHNICAL GUIDES',
  introduction:
    'These guides use local and synthetic examples to explain Schema Migrator and Atheros Search. Each includes source links and the limits of its checks.',
  contentsLabel: 'In this guide',
  sourcesTitle: 'Source code',
  sourcesNote:
    'The implementation behind the examples. Examples are educational inputs, not production records or measured results.',
  limitsLabel: 'Limits',
  relatedTitle: 'Related guides',
  productLinkLabel: 'Project documentation and synthetic sample',
  indexLinkLabel: 'Browse all technical guides',
  readLabel: 'Read guide',
} as const;

function repositorySource(path: string) {
  const repositories = [
    ['services/octopus/', 'octopus'],
    ['apps/schema-migrator/', 'schema-migrator'],
    ['apps/integration-console/', 'integration-console'],
  ] as const;
  for (const [prefix, repository] of repositories) {
    if (path.startsWith(prefix)) {
      return `https://github.com/zlovtnik/${repository}/blob/main/${path.slice(prefix.length)}`;
    }
  }
  return `https://github.com/zlovtnik/ssl-proxy/blob/main/${path}`;
}

export const guides: readonly Guide[] = [
  {
    slug: 'postgresql-migration-dry-run',
    title: 'PostgreSQL migration dry runs',
    description:
      'Run a two-file PostgreSQL migration example through discovery, validation, and an offline dry-run preview. Learn what the checks establish and what needs a target.',
    productId: 'migrator',
    eyebrow: 'POSTGRESQL / FILE REVIEW',
    introduction:
      'Schema Migrator can discover and validate SQL files and print their order without opening a database connection. The CLI collapses whitespace and shortens SQL longer than 120 characters. Review the complete source files alongside this preview. This local example creates a table before its index.',
    caveat: `${migratorCaveat} The public demonstration executes no SQL. An offline preview does not establish whether a target can execute the statements.`,
    sections: [
      {
        id: 'inputs',
        title: 'Prepare the complete two-file input',
        paragraphs: [
          'Use a local checkout of Schema Migrator, a JDK and sbt. Run the commands from apps/schema-migrator. Create a new empty directory named review-example and save only the two files below in its tables and indexes folders. Keep this disposable input separate from the repository SQL tree. No target credentials are needed for these offline commands.',
        ],
        examples: [
          {
            label: 'Local example directory. All listed folders exist',
            code: migrationExamples.ordering.tree.replace(
              /^sql\//,
              'review-example/',
            ),
            note: 'Empty folders avoid missing-folder discovery warnings. This example uses folder ordering, not a manifest.',
          },
          ...migrationExamples.ordering.files.map((file) => ({
            label: file.path,
            code: file.sql,
            note: 'Illustrative source SQL for the local example. It is not a production migration.',
          })),
        ],
        points: [
          'PostgreSQL discovery orders extensions, schemas, types, tables, indexes, functions, views, cron, then materialized_views. Filenames sort inside each folder.',
          'The object, folder, and depends_on headers declare the object and its dependency. The index names observations as its prerequisite.',
          'For a directory using core/manifest.yaml, apply_order determines the sequence instead. Unlisted SQL is reported as ignored.',
        ],
      },
      {
        id: 'discover-validate',
        title: 'Discover files, then review validation findings',
        paragraphs: [
          'The application output below was captured for the local example and excludes sbt startup messages. list reports order. validate reports file-specific findings. Warnings do not fail the command, while validation errors do.',
        ],
        examples: migrationExamples.preview.runs.slice(0, 2).map((run) => ({
          label: run.command.replace('./sql', './review-example'),
          code: run.output,
          note: run.note,
        })),
        points: [
          'The lowercase CREATE TABLE in this fixture still produces the shown idempotency warning. Read findings alongside the complete SQL rather than treating a zero exit status as proof of execution safety.',
          'As a separate negative test, an unterminated single-quoted SQL string produces a parsing error with the file path and a non-zero exit. Keep invalid test files out of the two-file preview input.',
        ],
      },
      {
        id: 'preview',
        title: 'Read the ordered preview beside the full files',
        paragraphs: [
          '--dry-run apply prints file paths and compacted SQL in apply order. It does not execute the table or index statement.',
        ],
        examples: migrationExamples.preview.runs.slice(3).map((run) => ({
          label: run.command.replace('./sql', './review-example'),
          code: run.output,
          note: run.note,
        })),
        points: [
          'The printer collapses whitespace and shortens SQL after 120 characters. Retain the full files as the review artifact. The displayed preview cannot be used as a complete deployment script.',
          'Check that each referenced table, type and extension precedes its dependent objects. Review destructive operations and transaction requirements in the full statements.',
        ],
      },
      {
        id: 'next-check',
        title: 'Choose the next check for the unresolved question',
        paragraphs: [
          'A file review answers what would be submitted, not what already exists or what a target will permit. Select the next step according to the evidence you still need.',
        ],
        table: {
          caption: 'Separate offline review from target-dependent checks',
          headers: ['Question', 'Check', 'Boundary'],
          rows: [
            [
              'Do files parse and dependencies resolve?',
              'Offline validation',
              'No target execution evidence',
            ],
            [
              'What structure exists now?',
              'Connected catalog drift inspection',
              'Findings require review. No automatic correction',
            ],
            [
              'Will these statements work with these data and permissions?',
              'Rehearsal on a non-production target',
              'Production locks, data, and concurrent activity can still differ',
            ],
          ],
        },
      },
    ],
    sources: [
      {
        label: 'CLI validation and offline command paths',
        href: repositorySource(
          'apps/schema-migrator/src/main/scala/com/sslproxy/schema/cli/Commands.scala',
        ),
        note: 'list, validate and dry-run apply use SQL-only configuration validation.',
      },
      {
        label: 'PostgreSQL folder order',
        href: repositorySource(
          'apps/schema-migrator/src/main/scala/com/sslproxy/schema/discovery/FolderOrder.scala',
        ),
        note: 'The supported folder sequence for this example.',
      },
      {
        label: 'Preview output formatting',
        href: repositorySource(
          'apps/schema-migrator/src/main/scala/com/sslproxy/schema/output/ReportPrinter.scala',
        ),
        note: 'File paths, warnings, errors and dry-run previews are printed as review output.',
      },
    ],
    related: ['postgresql-schema-drift', 'migration-checksum-mismatch'],
  },
  {
    slug: 'postgresql-schema-drift',
    title: 'Investigating PostgreSQL schema drift',
    description:
      'Compare expected PostgreSQL definitions, live catalog objects, and migration control state in a worked schema drift example. Separate detection from remediation.',
    productId: 'migrator',
    eyebrow: 'POSTGRESQL / CATALOG REVIEW',
    introduction:
      'Schema Migrator compares selected PostgreSQL catalog definitions and table presence, but does not compare column definitions or nullability. A clean report therefore cannot rule out column drift. The checks below compare expected objects and control records with the live catalog, separately from SQL-file checksum changes.',
    caveat: `${migratorCaveat} Catalog inspection needs a target connection. Drift findings do not correct the database, and a finding is not a safe migration plan by itself.`,
    sections: [
      {
        id: 'scope',
        title: 'Establish the expected state and target scope',
        paragraphs: [
          'Start with the reviewed SQL manifest and its control state, then identify the target database and schemas being inspected. A catalog read needs access to that target. Record when it was read so findings are not mistaken for a timeless view.',
        ],
        points: [
          'Keep manifest definitions, migration apply statuses, source paths and recorded checksums with the report.',
          'Check whether control state was available. A warning about unavailable control state leaves part of the comparison unresolved.',
          'A pending or failed apply status is a control-state issue, not proof that someone edited a catalog object manually.',
        ],
      },
      {
        id: 'example',
        title: 'Compare a synthetic expected catalog with an observed catalog',
        paragraphs: [
          'The following teaching example is constructed, not captured from a database. Assume tracked objects without a pending status have an applied control status. The final object is pending.',
        ],
        table: {
          caption:
            'Synthetic schema drift inputs and expected finding categories',
          headers: ['Object', 'Expected', 'Observed', 'Finding'],
          rows: [
            [
              'public.observations_source_idx',
              'Index on source',
              'Same index name, indexed column is observed_at',
              'definition_changed',
            ],
            [
              'public.observations_observed_at_idx',
              'Tracked index on observed_at',
              'Index absent',
              'missing_actual',
            ],
            [
              'public.review_notes',
              'Absent from manifest and control records',
              'Table present',
              'untracked_actual',
            ],
            [
              'public.observations_source_order_idx',
              'Tracked index. Apply_status=pending',
              'Index absent',
              'pending_or_failed_control',
            ],
          ],
        },
        points: [
          'A missing object can result from incomplete application or later removal. The category alone does not establish the cause.',
          'An untracked object may be an intended addition that has not been recorded. Compare ownership and change history before proposing removal.',
          'The pending index is reported through its control status rather than counted again as an ordinary missing object.',
        ],
      },
      {
        id: 'definitions',
        title: 'Read the definition behind a changed-index finding',
        paragraphs: [
          'Names are insufficient: the expected and observed object must also agree on the compared definition. This synthetic index comparison changes the indexed column while retaining the same index name.',
        ],
        examples: [
          {
            label: 'Synthetic expected and observed definitions',
            code: 'Expected: CREATE INDEX observations_source_idx\n          ON public.observations (source);\nObserved: CREATE INDEX observations_source_idx\n          ON public.observations (observed_at);\nFinding:  definition_changed',
            note: 'A condensed teaching view, not a literal API response. Retain the complete reported DDL for an actual review.',
          },
        ],
        points: [
          'Definition comparisons cover functions, procedures, triggers, views, materialized views and indexes. The reader checks table presence, but does not compare column definitions or nullability. Those need a separate check.',
          'An index definition finding describes structure, not how a proposed replacement will behave under load. Review data size, permissions and locking conditions before execution.',
        ],
      },
      {
        id: 'remediation',
        title: 'Turn a finding into a reviewed change',
        paragraphs: [
          'Preserve the observed definitions and check the source history. Decide whether the manifest or the live object reflects the intended design. Write a new ordered migration when a correction is needed, rehearse it against non-production data, and inspect the catalog again afterward.',
        ],
        points: [
          'Keep active ordered migrations append-only. Do not conceal drift by rewriting an already recorded file.',
          'Handle target credentials and DDL through the deployment workflow. Catalog inspection may create and drop temporary session views to normalize view definitions. It applies no permanent correction.',
          'A clean report establishes agreement within the inspected scope and comparison logic, not complete database health.',
        ],
      },
    ],
    sources: [
      {
        label: 'PostgreSQL drift diff engine',
        href: repositorySource(
          'apps/schema-migrator/src/main/scala/com/sslproxy/schema/server/PostgresDriftDiffEngine.scala',
        ),
        note: 'Finding types, control-state handling and expected-versus-observed comparisons.',
      },
      {
        label: 'PostgreSQL catalog reader',
        href: repositorySource(
          'apps/schema-migrator/src/main/scala/com/sslproxy/schema/server/PostgresCatalogReader.scala',
        ),
        note: 'The live catalog scope that supports drift inspection.',
      },
    ],
    related: ['migration-checksum-mismatch', 'postgresql-migration-dry-run'],
  },
  {
    slug: 'migration-checksum-mismatch',
    title: 'Migration checksum mismatches',
    description:
      'Reproduce a SQL-file checksum mismatch locally, interpret added, removed, and changed snapshot paths, and distinguish file integrity from PostgreSQL schema drift.',
    productId: 'migrator',
    eyebrow: 'POSTGRESQL / SOURCE INTEGRITY',
    introduction:
      'A migration checksum mismatch means the recorded file bytes and the current file bytes differ. It does not tell you whether a live table or index changed. Schema Migrator snapshots compare SQL files by path and SHA-256, keeping this question separate from catalog drift.',
    caveat: `${migratorCaveat} Equal checksums establish equal file content for the comparison. They do not prove successful execution or agreement with a live database.`,
    sections: [
      {
        id: 'reproduce',
        title: 'Reproduce a changed-file comparison without a database',
        paragraphs: [
          'Run this standard-library Python example in a temporary directory. It keeps the original SQL unchanged and adds a comment to a separate copy, so it demonstrates a mismatch without modifying an active migration.',
        ],
        examples: [
          {
            label: 'Local synthetic SQL-file comparison',
            code: String.raw`python3 - <<'PY'
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory

original = b"create table observations (id bigint primary key);\n"
with TemporaryDirectory() as directory:
    before = Path(directory) / "before.sql"
    after = Path(directory) / "after.sql"
    before.write_bytes(original)
    after.write_bytes(original + b"-- review note\n")
    base_hash = sha256(before.read_bytes()).hexdigest()
    compare_hash = sha256(after.read_bytes()).hexdigest()
    print("base_sha256:", base_hash)
    print("compare_sha256:", compare_hash)
    print("changed:", base_hash != compare_hash)
PY`,
            note: 'Both files are disposable inputs. The comment changes bytes even though it does not change the table definition.',
          },
          {
            label: 'Captured output from the disposable-file example',
            code: 'base_sha256: 750a67cd5c8cfcb2214b3ab0e3e68c7fd579221b005c70b9ca76597188db5b53\ncompare_sha256: 056db53ecbcb355def021845147df816ff383ace88b5664099dfaf06fd7e22bf\nchanged: True',
            note: 'These are actual SHA-256 values for the synthetic inputs above, not values from a migration run or database.',
          },
        ],
      },
      {
        id: 'interpret',
        title: 'Read the path and both checksums',
        paragraphs: [
          'Snapshot comparison matches files by path. A path present only in the newer snapshot is added. One present only in the base is removed. A path present in both is changed when its SHA-256 differs. Unchanged paths do not produce diff items.',
        ],
        table: {
          caption: 'Synthetic snapshot path comparison',
          headers: [
            'Path',
            'Base snapshot',
            'Comparison snapshot',
            'Diff category',
          ],
          rows: [
            [
              'tables/001_observations.sql',
              'Original bytes',
              'Same bytes plus a comment',
              'changed',
            ],
            ['indexes/002_observed_at.sql', 'Absent', 'New file', 'added'],
            ['views/003_review.sql', 'File present', 'Absent', 'removed'],
          ],
        },
        points: [
          'Keep the full before and after checksums and the original source available to the reviewer.',
          'A rename can appear as one removed path and one added path. The diff categorizes paths. It does not infer a semantic rename.',
          'Whitespace, line endings and comments can change a file checksum without changing database semantics. Inspect the actual diff before deciding on a correction.',
        ],
      },
      {
        id: 'decision',
        title: 'Resolve the discrepancy without erasing evidence',
        paragraphs: [
          'First check which source version was reviewed and recorded. If a recorded migration was accidentally edited, restore the reviewed bytes from version control. If the intended schema needs to change, add a new ordered migration rather than rewriting the old record.',
        ],
        points: [
          'For a file that has not been applied, follow the project review process and record the new reviewed version before execution.',
          'Do not replace a recorded checksum solely to make the mismatch disappear. That removes the evidence you need to understand the discrepancy.',
          'If the concern is the live database, perform catalog drift inspection separately. A file can change while the database stays the same, or the database can change while files stay identical.',
        ],
      },
    ],
    sources: [
      {
        label: 'SQL-file snapshot comparison',
        href: repositorySource(
          'apps/schema-migrator/src/main/scala/com/sslproxy/schema/store/SnapshotStore.scala',
        ),
        note: 'Diff items are added, removed or changed, with before and after SHA-256 values.',
      },
      {
        label: 'Migration planning',
        href: repositorySource(
          'apps/schema-migrator/src/main/scala/com/sslproxy/schema/engine/MigrationPlan.scala',
        ),
        note: 'Ordered SQL inputs remain separate from snapshot comparison.',
      },
    ],
    related: ['postgresql-schema-drift', 'postgresql-migration-dry-run'],
  },
  {
    slug: 'rogue-access-point-investigation',
    title: 'Investigating a suspected rogue access point',
    description:
      'Work through synthetic rogue access point observations using SSID, BSSID, channel, time, and authorized-network context. Separate wireless indicators from confirmed incidents.',
    productId: 'search',
    eyebrow: 'WIRELESS / ACCESS POINT REVIEW',
    introduction:
      'A suspicious SSID or BSSID is a lead to investigate. Start with the monitored site and the observation time, then compare the advertised network with the site inventory. Atheros Sensor raises configured indicators. Atheros Search helps review the observations behind them.',
    caveat: `${searchCaveat} A rogue access point indicator does not prove an attack or an unauthorized physical device.`,
    sections: [
      {
        id: 'prerequisites',
        title: 'Record what the sensor could observe',
        paragraphs: [
          'Passive capture requires Linux, monitor-mode Wi-Fi hardware, and configured channels. Establish authorization, collection scope, access and retention arrangements before capture. Record sensor location, interface, time range and channel coverage, and use an up-to-date authorized-network list for that site.',
        ],
        points: [
          'A sensor observing channel 6 cannot establish that nothing happened on unmonitored channels.',
          'The detector reviews beacon and probe-response observations. An advertised network name alone does not establish a client connection.',
          'Record maintenance windows, managed AP changes and the age of the authorized inventory alongside the observation.',
          'MAC randomization and spoofing prevent an observed address from establishing a physical device identity. Corroborate a lead against site inventory and independent evidence.',
          'This example does not establish WPA3, 6 GHz, or multi-link coverage. Record the hardware, driver, band and frame types actually observed before extending a conclusion to those environments.',
        ],
      },
      {
        id: 'records',
        title: 'Follow a synthetic SSID discrepancy',
        paragraphs: [
          'In this constructed example, the site inventory lists LabNet as an authorized network. The two rows are educational observation summaries, not sensor payloads or production records.',
        ],
        table: {
          caption: 'Synthetic observations at lab-west, sensor-lab-01',
          headers: [
            'Time (UTC)',
            'SSID',
            'BSSID',
            'Channel',
            'Observed security',
          ],
          rows: [
            [
              '2026-10-08 10:00:00',
              'LabNet',
              '02:00:00:00:00:10',
              '6',
              'Encryption advertised',
            ],
            [
              '2026-10-08 10:00:05',
              'LabNet',
              '02:00:00:00:00:20',
              '6',
              'No encryption advertised',
            ],
          ],
        },
        examples: [
          {
            label: 'Synthetic detector inputs and review reason',
            code: 'Configured known SSID: LabNet\nObserved SSID: LabNet\nObserved security_flags: 0\nReview reason: open_authorized_ssid',
            note: 'This matches the implementation condition: a known SSID with security_flags equal to zero. It is a reason to inspect the evidence, not an incident verdict.',
          },
        ],
      },
      {
        id: 'investigate',
        title: 'Review the indicator against the supporting observations',
        paragraphs: [
          'Scope the review to lab-west and the observation interval. Inspect the beacon or probe-response fields and related records for each BSSID. Preserve the source keys, timestamps and detector reasons so another analyst can follow the same evidence.',
        ],
        points: [
          'Check the configured network list: was an open guest network, temporary AP or recent controller change omitted?',
          'Compare the AP inventory and maintenance history. An SSID shared by multiple BSSIDs can be expected in a managed deployment.',
          'Review related observations before deciding whether the pattern persists. The detector also has reasons for similar SSIDs, changed BSSID-to-SSID mappings, and channel or vendor conflicts. Each reason needs its own context.',
          'Use location or device identity suggestions as review candidates. Do not turn an observed address into a confirmed owner or physical asset.',
        ],
      },
      {
        id: 'outcome',
        title: 'Document uncertainty as part of the finding',
        paragraphs: [
          'A useful investigation note states the site, time window, observed fields, triggered reason, inventory comparison and unresolved questions. A possible explanation such as maintenance must be corroborated rather than assumed.',
        ],
        examples: [
          {
            label: 'Synthetic analyst note',
            code: 'Site: lab-west\nWindow: 10:00:00-10:00:05 UTC\nLead: known SSID LabNet observed without advertised encryption\nEvidence: BSSID 02:00:00:00:00:20, channel 6\nInventory check: unresolved. Ask the site owner to confirm AP changes\nConclusion: review candidate. No connection or device identity confirmed',
            note: 'An example of recording the evidence boundary. No message is sent by this guide.',
          },
        ],
        points: [
          'Capture placement, missed frames and incomplete channel coverage can leave gaps.',
          'A stale authorized list or a legitimate configuration change can explain a lead. Close the finding only after recording the supporting check.',
        ],
      },
    ],
    sources: [
      {
        label: 'Rogue access point detection conditions',
        href: repositorySource(
          'services/atheros-sensor/src/detect_state_sections/rogue_deauth.rs',
        ),
        note: 'Known open SSIDs, similar names, mapping changes and conflict reasons are heuristic leads.',
      },
      {
        label: 'Sensor capture and configuration',
        href: repositorySource('services/atheros-sensor/README.md'),
        note: 'Monitor-mode prerequisites and configured capture scope.',
      },
      {
        label: 'Search review surfaces',
        href: repositorySource(
          'apps/integration-console/atheros-search/README.md',
        ),
        note: 'Search, inventory and record explanation capabilities.',
      },
    ],
    related: [
      'wifi-deauthentication-investigation',
      'hybrid-search-network-observations',
    ],
  },
  {
    slug: 'wifi-deauthentication-investigation',
    title: 'Investigating Wi-Fi deauthentication observations',
    description:
      'Use a synthetic time-window example to review Wi-Fi deauthentication and disassociation indicators, capture scope, detector thresholds, and corroborating evidence.',
    productId: 'search',
    eyebrow: 'WIRELESS / TIME-WINDOW REVIEW',
    introduction:
      'A burst of observed deauthentication frames needs a scoped investigation. The sensor counts deauthentication and disassociation observations in a configured window and raises an indicator when the threshold is reached. The count establishes observed frames, not confirmed disruption or attacker identity.',
    caveat: `${searchCaveat} Observed management frames and a threshold crossing do not prove that a client disconnected, that an attack succeeded, or who transmitted the frames.`,
    sections: [
      {
        id: 'scope',
        title: 'Keep capture scope and detector settings together',
        paragraphs: [
          'Use monitor-mode hardware on the channels under review and record the sensor, site, interval and configuration. Atheros Sensor groups valid BSSIDs separately. When a BSSID cannot be parsed, it uses a fallback source identity. Both deauthentication and disassociation frames count.',
        ],
        points: [
          'A zero threshold or zero window disables this detector path.',
          'A cooldown can suppress repeated alerts even when frames continue to be observed. Alert totals are not raw frame totals.',
          'Missing frames, unmonitored channels and capture placement limit the interpretation of both positive and absent findings.',
        ],
      },
      {
        id: 'window',
        title: 'Reproduce the reasoning with a small synthetic window',
        paragraphs: [
          'For this teaching example, choose a threshold of 3 frames and a 10-second window. These are example settings, not production defaults or recommended thresholds. All four observations have BSSID 02:00:00:00:00:30 at lab-west on channel 6.',
        ],
        table: {
          caption: 'Synthetic frame sequence for one BSSID',
          headers: [
            'Time (UTC)',
            'Frame subtype',
            'Count at this observation',
            'Interpretation',
          ],
          rows: [
            ['10:00:00', 'deauthentication', '1', 'Below example threshold'],
            [
              '10:00:01',
              'disassociation',
              '2',
              'Also counted by this detector',
            ],
            [
              '10:00:02',
              'deauthentication',
              '3',
              'Threshold reached. Eligible to alert',
            ],
            [
              '10:00:03',
              'deauthentication',
              '4',
              'Still observed. Cooldown may suppress another alert',
            ],
          ],
        },
        examples: [
          {
            label: 'Reproducible teaching count. Not the sensor implementation',
            code: `python3 - <<'PY'
times = [0, 1, 2, 3]
window_seconds = 10
threshold = 3
for index, now in enumerate(times):
    count = sum(now - time < window_seconds for time in times[:index + 1])
    print(now, count, count >= threshold)
PY`,
            note: 'The four timestamps stay inside one window. The actual detector uses per-second buckets and a frame-time cooldown. This small example illustrates the threshold only.',
          },
          {
            label: 'Captured output from the teaching count',
            code: '0 1 False\n1 2 False\n2 3 True\n3 4 True',
            note: 'Each row shows elapsed seconds, observed count and whether the example threshold is reached. It is not sensor alert output.',
          },
        ],
      },
      {
        id: 'corroborate',
        title: 'Check the lead against nearby records',
        paragraphs: [
          'Review the source and receiver addresses, reason fields where decoded, BSSID, channel and timestamps in the original audit observations. Compare records before and after the burst, then check AP or client operational logs when available.',
        ],
        points: [
          'Look for related association and authentication observations, but do not infer a complete session from a partial passive capture.',
          'Compare the interval with maintenance, AP restarts and client behavior. A frame subtype by itself does not reveal why the frame was transmitted.',
          'Inspect PMF-related context when available. A PMF indicator remains a separate heuristic and does not prove a client accepted or rejected the frame.',
          'Retain the configured threshold and cooldown with the investigation so a later analyst can explain why one alert represents several observations.',
        ],
      },
      {
        id: 'report',
        title: 'Report the observation and the unresolved impact separately',
        paragraphs: [
          'A defensible note can say that three matching frames were observed in the example window and that the configured condition was reached. It should state separately whether client impact was corroborated, which channels were monitored, and what identity remains unknown.',
        ],
        examples: [
          {
            label: 'Synthetic investigation conclusion',
            code: 'Observed: 3 deauthentication/disassociation frames in the example window\nScope: lab-west, sensor-lab-01, channel 6, BSSID 02:00:00:00:00:30\nDetector condition: example threshold reached\nClient impact: not established by passive observations\nTransmitter identity: not confirmed',
            note: 'This records a lead without claiming a successful attack or a current connection.',
          },
        ],
      },
    ],
    sources: [
      {
        label: 'Deauthentication counter and cooldown',
        href: repositorySource(
          'services/atheros-sensor/src/detect_state_sections/rogue_deauth.rs',
        ),
        note: 'Accepted subtypes, threshold comparison, grouping and cooldown behavior.',
      },
      {
        label: 'Wireless audit model',
        href: repositorySource('services/atheros-sensor/src/model.rs'),
        note: 'Published observations retain sensor, site, time and decoded frame context.',
      },
      {
        label: 'PMF review heuristics',
        href: repositorySource(
          'services/atheros-sensor/src/detect_state_sections/pmf.rs',
        ),
        note: 'PMF-related patterns are additional indicators, not proof of client behavior.',
      },
    ],
    related: [
      'rogue-access-point-investigation',
      'hybrid-search-network-observations',
    ],
  },
  {
    slug: 'hybrid-search-network-observations',
    title: 'Hybrid search over network observations',
    description:
      'Compare term, vector, and hybrid retrieval on the same synthetic observations. Work through weighted reciprocal-rank fusion and interpret explain data and sparse fallback.',
    productId: 'search',
    eyebrow: 'SEARCH / RETRIEVAL REVIEW',
    introduction:
      'Atheros Search combines term and vector results with weighted reciprocal-rank fusion. This example follows the same records through both rankings and calculates their fused scores. It includes no measured accuracy or latency comparison.',
    caveat: `${searchCaveat} Ranking is a retrieval signal, not a probability of an incident. This guide publishes no measured relevance, latency or storage result.`,
    sections: [
      {
        id: 'data',
        title: 'Fix the query and scope before comparing modes',
        paragraphs: [
          'Use the same dataset, source kinds, site filter, observation interval and result budget for each mode. This synthetic text collection illustrates candidate ranking. It is not an ingested sensor payload or an actual embedding run.',
        ],
        table: {
          caption: 'Synthetic observations, all scoped to lab-west',
          headers: ['Record', 'Observation summary'],
          rows: [
            ['A', 'Deauthentication frames observed on channel 6'],
            [
              'B',
              'Management frames coincide with a reported wireless interruption',
            ],
            [
              'C',
              'AP maintenance note mentions deauthentication during review',
            ],
          ],
        },
        examples: [
          {
            label: 'Fixed teaching query and scope',
            code: 'Query: wireless deauthentication\nSite: lab-west\nObservation interval: 2026-10-08 10:00-10:10 UTC\nResult budget: 3\nCompare: sparse, dense, hybrid',
            note: 'Conceptual inputs, not a literal request body. A real comparison must preserve the same service filters and record collection.',
          },
        ],
      },
      {
        id: 'modes',
        title: 'Keep term and vector evidence separate',
        paragraphs: [
          'Sparse retrieval uses PostgreSQL full-text term matching. Dense retrieval compares query embeddings with stored embeddings for the configured model. Hybrid retrieval merges their candidate lists by source key rather than adding incomparable raw keyword and cosine scores.',
        ],
        table: {
          caption:
            'Assigned teaching ranks on the same data. Not measured retrieval results',
          headers: [
            'Record',
            'Sparse rank',
            'Dense rank',
            'Review interpretation',
          ],
          rows: [
            ['A', '1', '2', 'Appears in both candidate lists'],
            [
              'B',
              'Not returned',
              '1',
              'Semantic candidate in the assigned example',
            ],
            [
              'C',
              '2',
              'Not returned',
              'Term candidate in the assigned example',
            ],
          ],
        },
        points: [
          'Missing from a returned candidate list does not mean the record is absent from the dataset.',
          'Dense retrieval depends on embedding availability and model coverage. Keep processing health and coverage with a real evaluation.',
          'Do not label these assigned ranks as a benchmark. Measured relevance needs independently judged queries and captured results.',
        ],
      },
      {
        id: 'fusion',
        title: 'Calculate an explainable fusion stage',
        paragraphs: [
          'The implementation uses k = 60. A dense candidate contributes alpha / (60 + rank). A sparse candidate contributes (1 - alpha) / (60 + rank). For the example alpha = 0.5, the record appearing in both lists accumulates both contributions. These values are arithmetic outputs for the assigned ranks, not service measurements.',
        ],
        examples: [
          {
            label: 'Synthetic weighted RRF calculation. Alpha = 0.5',
            code: 'A = 0.5 / (60 + 2) + 0.5 / (60 + 1) = 0.016261\nB = 0.5 / (60 + 1)                      = 0.008197\nC = 0.5 / (60 + 2)                      = 0.008065\nFusion order: A, B, C',
            note: 'Values are rounded to six decimals. This illustrates the fusion stage, not an incident confidence score.',
          },
        ],
        points: [
          'Candidates are deduplicated by source key. Equal final scores use source-key ordering as the tie-break.',
          'Changing alpha changes the relative weight of the two ranked lists. It does not calibrate the result into a probability.',
          'Retain the selected record and the original result envelope when explaining a real result. A later search can observe a changed collection or embedding state.',
        ],
      },
      {
        id: 'explain',
        title: 'Read the available explanation and actual mode used',
        paragraphs: [
          'A scoped explanation resolves the selected record within the supplied scope and computes its sparse score directly. It does not invent dense or fusion ranks that are unavailable. Preserve dense and fusion information from the original response when it exists.',
        ],
        points: [
          'Check mode_used, fallback_code and the returned candidate counts. A request for hybrid search can return sparse results when the embedding leg is unavailable or lacks coverage.',
          'A fallback reason explains retrieval availability, not the truth of an observation. Do not describe a sparse fallback result as successful semantic retrieval.',
          'Open the source record to review time, site, identifiers and decoded evidence. Relevance alone does not establish a current connection or physical device identity.',
          'For a real evaluation, record dataset version, model, filters, queries, judgments, returned ranks and fallback state before discussing measured quality.',
        ],
      },
    ],
    sources: [
      {
        label: 'Weighted reciprocal-rank fusion',
        href: repositorySource(
          'apps/integration-console/atheros-search/internal/search/fusion.go',
        ),
        note: 'Rank weighting, source-key deduplication and deterministic tie-breaking.',
      },
      {
        label: 'Fusion constant and raw result fields',
        href: repositorySource(
          'apps/integration-console/atheros-search/internal/search/types.go',
        ),
        note: 'The implementation sets rrfK to 60.',
      },
      {
        label: 'Search orchestration and fallback',
        href: repositorySource(
          'apps/integration-console/atheros-search/internal/search/service.go',
        ),
        note: 'Requested and actual modes, candidate counts and semantic fallback behavior.',
      },
      {
        label: 'Scoped record explanation',
        href: repositorySource(
          'apps/integration-console/atheros-search/internal/search/scoped_explain.go',
        ),
        note: 'Direct sparse-score explanation preserves the selected record and scope.',
      },
    ],
    related: [
      'rogue-access-point-investigation',
      'wifi-deauthentication-investigation',
    ],
  },
];

export const guidePath = (slug: string) => `/guides/${slug}/`;

export function getGuide(slug: string): Guide {
  const guide = guides.find((item) => item.slug === slug);
  if (!guide) throw new Error(`Unknown guide: ${slug}`);
  return guide;
}
