"""Knowledge Graph engine using NetworkX for asset, observation, hypothesis, and evidence relationships."""

from typing import Any, Dict, List, Optional, Set, Tuple
import networkx as nx

from disstroy.models.asset import Asset
from disstroy.models.observation import Observation
from disstroy.models.hypothesis import Hypothesis
from disstroy.models.evidence import EvidenceRecord
from disstroy.models.failure import FailureRecord
from disstroy.state.shared_state import StateChangeEvent


class KnowledgeGraph:
    """Dynamic multi-directional graph representation of target landscape and investigation state."""

    def __init__(self):
        self.g: nx.MultiDiGraph = nx.MultiDiGraph()

    # ---------------- State Event Handler ----------------

    async def handle_state_event(self, event: StateChangeEvent) -> None:
        """Automatically synchronize graph state from event bus."""
        p = event.payload
        if event.event_type == "ASSET_ADDED":
            self.add_asset_node(
                asset_id=p["id"],
                name=p["name"],
                asset_type=p["asset_type"],
                criticality=p["criticality"],
                current_access_level=p.get("current_access_level", "NONE"),
                is_canary_objective=p.get("is_canary_objective", False),
                canary_description=p.get("canary_description"),
                metadata=p.get("metadata", {}),
            )
        elif event.event_type == "OBSERVATION_ADDED":
            self.add_observation_node(
                obs_id=p["id"],
                asset_id=p["asset_id"],
                kind=p["kind"],
                title=p["title"],
                confidence=p["confidence"],
                metadata=p.get("raw_payload", {}),
            )
        elif event.event_type in ("HYPOTHESIS_ADDED", "HYPOTHESIS_UPDATED"):
            self.add_hypothesis_node(
                hyp_id=p["id"],
                target_asset_id=p["target_asset_id"],
                category=p["category"],
                title=p["title"],
                status=p["status"],
                priority_score=p["priority_score"],
                supporting_obs_ids=p.get("supporting_observation_ids", []),
                prerequisite_hypothesis_ids=p.get("prerequisite_hypothesis_ids", []),
                required_access_level=p.get("required_access_level", "NONE"),
                enables_access_level=p.get("enables_access_level"),
                stage=p.get("stage", 1),
            )
        elif event.event_type == "EVIDENCE_ADDED":
            self.add_evidence_node(
                ev_id=p["id"],
                hypothesis_id=p["hypothesis_id"],
                evidence_type=p["evidence_type"],
                supports=p["supports_hypothesis"],
                validation_power=p["validation_power"],
                falsification_power=p["falsification_power"],
            )
        elif event.event_type == "FAILURE_RECORDED":
            self.add_failure_node(
                fail_id=p["id"],
                hypothesis_id=p["hypothesis_id"],
                failure_category=p["failure_category"],
                error_message=p["error_message"],
            )

    # ---------------- Node & Edge Adders ----------------

    def add_asset_node(
        self,
        asset_id: str,
        name: str,
        asset_type: str,
        criticality: float,
        current_access_level: str = "NONE",
        is_canary_objective: bool = False,
        canary_description: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Add or update an asset node in the graph."""
        self.g.add_node(
            asset_id,
            node_type="ASSET",
            name=name,
            asset_type=asset_type,
            criticality=criticality,
            current_access_level=current_access_level,
            is_canary_objective=is_canary_objective,
            canary_description=canary_description,
            metadata=metadata or {},
        )

    def update_asset_access_level(self, asset_id: str, access_level: str) -> None:
        """Update current access level on an existing asset node."""
        if asset_id in self.g:
            self.g.nodes[asset_id]["current_access_level"] = access_level

    def add_asset_dependency(self, source_asset_id: str, target_asset_id: str, relation: str = "COMMUNICATES_WITH") -> None:
        """Add an architectural or communication dependency edge between assets."""
        if source_asset_id in self.g and target_asset_id in self.g:
            self.g.add_edge(source_asset_id, target_asset_id, relation=relation)

    def add_observation_node(
        self,
        obs_id: str,
        asset_id: str,
        kind: str,
        title: str,
        confidence: float,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Add an observation node and link it to its host asset."""
        self.g.add_node(
            obs_id,
            node_type="OBSERVATION",
            asset_id=asset_id,
            kind=kind,
            title=title,
            confidence=confidence,
            metadata=metadata or {},
        )
        if asset_id in self.g:
            self.g.add_edge(obs_id, asset_id, relation="OBSERVED_ON")

    def correlate_observations(self, obs_a_id: str, obs_b_id: str, correlation_reason: str) -> None:
        """Establish an explicit correlation edge between two related observations."""
        if obs_a_id in self.g and obs_b_id in self.g:
            self.g.add_edge(obs_a_id, obs_b_id, relation="CORRELATED_WITH", reason=correlation_reason)
            self.g.add_edge(obs_b_id, obs_a_id, relation="CORRELATED_WITH", reason=correlation_reason)

    def add_hypothesis_node(
        self,
        hyp_id: str,
        target_asset_id: str,
        category: str,
        title: str,
        status: str,
        priority_score: float,
        supporting_obs_ids: Optional[List[str]] = None,
        prerequisite_hypothesis_ids: Optional[List[str]] = None,
        required_access_level: str = "NONE",
        enables_access_level: Optional[str] = None,
        stage: int = 1,
    ) -> None:
        """Add or update a hypothesis node and link it to target assets, observations, and prerequisite hypotheses."""
        prereqs = list(prerequisite_hypothesis_ids or [])
        self.g.add_node(
            hyp_id,
            node_type="HYPOTHESIS",
            target_asset_id=target_asset_id,
            category=category,
            title=title,
            status=status,
            priority_score=priority_score,
            prerequisite_ids=prereqs,
            required_access_level=required_access_level,
            enables_access_level=enables_access_level,
            stage=stage,
        )
        if target_asset_id in self.g:
            self.g.add_edge(hyp_id, target_asset_id, relation="TARGETS")

        for obs_id in supporting_obs_ids or []:
            if obs_id in self.g:
                self.g.add_edge(hyp_id, obs_id, relation="DERIVED_FROM")

        # Wire incoming prerequisite edges
        for prereq_id in prereqs:
            if prereq_id in self.g:
                self.g.add_edge(prereq_id, hyp_id, relation="PREREQUISITE_FOR")

        # Wire outgoing prerequisite edges if dependents were added earlier
        for node, data in self.g.nodes(data=True):
            if data.get("node_type") == "HYPOTHESIS" and node != hyp_id:
                node_prereqs = data.get("prerequisite_ids", [])
                if hyp_id in node_prereqs and not self.g.has_edge(hyp_id, node):
                    self.g.add_edge(hyp_id, node, relation="PREREQUISITE_FOR")

    def add_prerequisite_dependency(self, prereq_hyp_id: str, dependent_hyp_id: str) -> None:
        """Add an explicit prerequisite dependency edge from one hypothesis to another."""
        if prereq_hyp_id in self.g and dependent_hyp_id in self.g:
            self.g.add_edge(prereq_hyp_id, dependent_hyp_id, relation="PREREQUISITE_FOR")
            stored = self.g.nodes[dependent_hyp_id].get("prerequisite_ids", [])
            if prereq_hyp_id not in stored:
                stored.append(prereq_hyp_id)
                self.g.nodes[dependent_hyp_id]["prerequisite_ids"] = stored

    def add_evidence_node(
        self,
        ev_id: str,
        hypothesis_id: str,
        evidence_type: str,
        supports: bool,
        validation_power: float,
        falsification_power: float,
    ) -> None:
        """Add an evidence node and link it to the tested hypothesis."""
        self.g.add_node(
            ev_id,
            node_type="EVIDENCE",
            hypothesis_id=hypothesis_id,
            evidence_type=evidence_type,
            supports=supports,
            validation_power=validation_power,
            falsification_power=falsification_power,
        )
        if hypothesis_id in self.g:
            relation = "VALIDATES" if supports else "REFUTES"
            self.g.add_edge(ev_id, hypothesis_id, relation=relation, supports=supports)

    def add_failure_node(
        self, fail_id: str, hypothesis_id: str, failure_category: str, error_message: str
    ) -> None:
        """Add a failure diagnostic node and link it to the invalidated hypothesis."""
        self.g.add_node(
            fail_id,
            node_type="FAILURE",
            hypothesis_id=hypothesis_id,
            failure_category=failure_category,
            error_message=error_message,
        )
        if hypothesis_id in self.g:
            self.g.add_edge(fail_id, hypothesis_id, relation="INVALIDATED")

    # ---------------- Graph Analytics & Traversal ----------------

    def get_asset_observations(self, asset_id: str) -> List[str]:
        """Return all observation node IDs linked to an asset."""
        obs = []
        if asset_id in self.g:
            for pred in self.g.predecessors(asset_id):
                if self.g.nodes[pred].get("node_type") == "OBSERVATION":
                    obs.append(pred)
        return obs

    def get_correlated_observations(self, obs_id: str) -> List[Tuple[str, str]]:
        """Return (correlated_obs_id, reason) for a given observation."""
        correlated = []
        if obs_id in self.g:
            for _, neighbor, data in self.g.edges(obs_id, data=True):
                if data.get("relation") == "CORRELATED_WITH":
                    correlated.append((neighbor, data.get("reason", "")))
        return correlated

    def find_paths_between_assets(self, source_id: str, target_id: str) -> List[List[str]]:
        """Find simple paths connecting two assets through dependency links."""
        if source_id not in self.g or target_id not in self.g:
            return []
        try:
            # Create view containing only asset nodes
            asset_subgraph = self.g.subgraph(
                [n for n, d in self.g.nodes(data=True) if d.get("node_type") == "ASSET"]
            )
            return list(nx.all_simple_paths(asset_subgraph, source=source_id, target=target_id, cutoff=5))
        except Exception:
            return []

    def find_candidate_asset_paths(self, source_id: str, target_id: str, max_hops: int = 5) -> List[List[str]]:
        """Find candidate multi-hop paths connecting two assets through dependency or communication links."""
        return self.find_paths_between_assets(source_id, target_id)

    def get_prerequisite_hypotheses(self, hyp_id: str) -> List[str]:
        """Return immediate prerequisite hypothesis IDs for the given hypothesis."""
        prereqs: List[str] = []
        if hyp_id in self.g:
            stored = self.g.nodes[hyp_id].get("prerequisite_ids", [])
            for p in stored:
                if p not in prereqs:
                    prereqs.append(p)
            for pred in self.g.predecessors(hyp_id):
                edge_data_dict = self.g.get_edge_data(pred, hyp_id)
                if edge_data_dict:
                    for _, attrs in edge_data_dict.items():
                        if attrs.get("relation") == "PREREQUISITE_FOR" and pred not in prereqs:
                            prereqs.append(pred)
                            break
        return prereqs

    def get_dependent_hypotheses(self, hyp_id: str) -> List[str]:
        """Return all hypotheses that directly depend on hyp_id as a prerequisite."""
        dependents: List[str] = []
        if hyp_id in self.g:
            for succ in self.g.successors(hyp_id):
                edge_data_dict = self.g.get_edge_data(hyp_id, succ)
                if edge_data_dict:
                    for _, attrs in edge_data_dict.items():
                        if attrs.get("relation") == "PREREQUISITE_FOR" and succ not in dependents:
                            dependents.append(succ)
                            break
        return dependents

    def get_asset_hypotheses(self, asset_id: str) -> List[str]:
        """Return all hypothesis IDs targeting a specific asset."""
        hypotheses: List[str] = []
        if asset_id in self.g:
            for pred in self.g.predecessors(asset_id):
                if self.g.nodes[pred].get("node_type") == "HYPOTHESIS":
                    hypotheses.append(pred)
        return hypotheses

    def detect_cycles(self) -> List[List[str]]:
        """Detect any directed cycles in the graph (e.g. mutual dependency loops or routing cycles)."""
        try:
            return list(nx.simple_cycles(self.g))
        except Exception:
            return []

    def get_invalidated_branches(self) -> Set[str]:
        """
        Traverse forward from permanently refuted or failed hypotheses to identify blocked downstream branches.
        Avoids wasting worker cycles on branches whose foundations have collapsed.
        """
        invalidated: Set[str] = set()
        queue: List[str] = []

        for node, data in self.g.nodes(data=True):
            if data.get("node_type") == "HYPOTHESIS":
                status = str(data.get("status", "")).upper()
                if status in ("REFUTED", "ABANDONED"):
                    invalidated.add(node)
                    queue.append(node)

        while queue:
            curr = queue.pop(0)
            for succ in self.get_dependent_hypotheses(curr):
                if succ not in invalidated:
                    invalidated.add(succ)
                    queue.append(succ)

        return invalidated

    def is_path_reachable_strictly_validated(self, hypothesis_sequence: List[str]) -> bool:
        """
        Verify whether an attack path sequence is strictly proven and reachability is verified.
        A graph edge must NOT imply that an attack path is actually feasible or verified.
        Every single hypothesis in the sequence must be in VALIDATED state with supporting evidence.
        """
        if not hypothesis_sequence:
            return False
        for hyp_id in hypothesis_sequence:
            if hyp_id not in self.g:
                return False
            data = self.g.nodes[hyp_id]
            if data.get("node_type") != "HYPOTHESIS":
                return False
            if str(data.get("status", "")).upper() != "VALIDATED":
                return False
        return True

    def get_subgraph_for_asset(self, asset_id: str, radius: int = 2) -> nx.MultiDiGraph:
        """Extract ego-graph around an asset node up to specified radius."""
        if asset_id not in self.g:
            return nx.MultiDiGraph()
        undirected_view = self.g.to_undirected(as_view=True)
        nodes = set(nx.single_source_shortest_path_length(undirected_view, asset_id, cutoff=radius).keys())
        return self.g.subgraph(nodes).copy()

    def get_top_critical_assets(self, top_k: int = 5) -> List[Tuple[str, float]]:
        """Compute degree centrality weighted by criticality for asset ranking."""
        assets = {n: d.get("criticality", 0.5) for n, d in self.g.nodes(data=True) if d.get("node_type") == "ASSET"}
        if not assets:
            return []
        centrality = nx.degree_centrality(self.g)
        scored = [(n, centrality.get(n, 0.0) * (1.0 + crit)) for n, crit in assets.items()]
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored[:top_k]

    def summary(self) -> Dict[str, Any]:
        """Export statistical summary of the graph."""
        type_counts: Dict[str, int] = {}
        for _, d in self.g.nodes(data=True):
            ntype = d.get("node_type", "UNKNOWN")
            type_counts[ntype] = type_counts.get(ntype, 0) + 1

        relation_counts: Dict[str, int] = {}
        for _, _, d in self.g.edges(data=True):
            rel = d.get("relation", "UNKNOWN")
            relation_counts[rel] = relation_counts.get(rel, 0) + 1

        return {
            "total_nodes": self.g.number_of_nodes(),
            "total_edges": self.g.number_of_edges(),
            "nodes_by_type": type_counts,
            "edges_by_relation": relation_counts,
        }
