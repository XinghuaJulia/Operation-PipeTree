General idea of project:

Parser:
 - start w one dataset first, gather the events
 - store in a lightweight db (e.g.) sqlite
 - parse it into timestamps, hosts, users, processes, network destinations, hashes, and event IDs.


Indicator Enrichment:
- Extract domain, IP, URL, Hashes
- Query public threat intel sharing platforms 
- Record source, query time, confidence, and enrichment status


Threat Modelling and Visualisation:
- Have PiVy's graph showing the nodes
- Use the Diamond Model: adversary, infra, capability, victim
- MITRE mapping




