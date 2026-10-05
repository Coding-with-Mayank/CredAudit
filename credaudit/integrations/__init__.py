"""External tools as evidence sources.

Hydra, Medusa, ncrack, Hashcat, John, and Nuclei/scan4all remain the
actual credential-testing/cracking/scanning engines -- CredAudit does
not reimplement any of them (see `credaudit/modules/{online,offline,recon}.py`,
which own scope-checked invocation of each binary). What lives in this
package is the other half: turning each tool's raw output into
`core.evidence.Evidence`, so from the correlation engine, risk engine,
and reporting layer's point of view, "a nuclei finding," "a cracked
hashcat password," and "a hydra valid pair" are all just evidence with a
`source` field -- not three different data shapes to special-case.

    credaudit.integrations.nuclei   -> credaudit.analyzers.vulnerabilities
    credaudit.integrations.hashcat  -> credaudit.analyzers.credentials
    credaudit.integrations.hydra    -> confirmed-access evidence directly
                                        (a valid pair found live is a
                                        directly observed fact, not
                                        something to re-derive)
"""
