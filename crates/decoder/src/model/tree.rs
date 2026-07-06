//! The logical concurrency tree: `select!`/`join!` fan-out and spawn
//! relationships as a tree, not a flattened stack (`CLAUDE.md` "Mental
//! model").

use std::collections::BTreeMap;

use super::ids::TaskId;
use super::task::TaskNode;
use crate::error::DecoderError;

/// A reconstructed logical concurrency tree: the output of
/// [`crate::SemanticDecoder::decode_tasks`].
///
/// Built once via [`TaskTree::try_from_nodes`] and then immutable. Children
/// are indexed by parent at construction time, in the order the nodes were
/// given — this preserves branch order (e.g. `select!` arm order) without
/// requiring each [`TaskNode`] to carry a second, independently-mutable
/// `children` list that could drift out of sync with `parent`.
#[derive(Debug, Clone)]
pub struct TaskTree {
    nodes: BTreeMap<TaskId, TaskNode>,
    children: BTreeMap<TaskId, Vec<TaskId>>,
    roots: Vec<TaskId>,
}

impl TaskTree {
    /// Build a tree from a flat list of nodes.
    ///
    /// # Errors
    /// Returns [`DecoderError::InvalidTaskTree`] if two nodes share an id,
    /// or if a node's `parent` does not refer to another node in the same
    /// list.
    pub fn try_from_nodes(nodes: Vec<TaskNode>) -> Result<Self, DecoderError> {
        let mut by_id = BTreeMap::new();
        for node in nodes {
            if by_id.insert(node.id, node).is_some() {
                return Err(DecoderError::InvalidTaskTree {
                    reason: "duplicate task id".to_string(),
                });
            }
        }

        let mut children: BTreeMap<TaskId, Vec<TaskId>> = BTreeMap::new();
        let mut roots = Vec::new();
        for node in by_id.values() {
            match node.parent {
                Some(parent) if by_id.contains_key(&parent) => {
                    children.entry(parent).or_default().push(node.id);
                }
                Some(_) => {
                    return Err(DecoderError::InvalidTaskTree {
                        reason: format!("task {:?} has a dangling parent reference", node.id),
                    });
                }
                None => roots.push(node.id),
            }
        }

        Ok(Self {
            nodes: by_id,
            children,
            roots,
        })
    }

    /// The root task ids (spawned by nothing else in this tree), in the
    /// order they were given to [`Self::try_from_nodes`].
    #[must_use]
    pub fn roots(&self) -> &[TaskId] {
        &self.roots
    }

    /// Look up a node by id.
    #[must_use]
    pub fn node(&self, id: TaskId) -> Option<&TaskNode> {
        self.nodes.get(&id)
    }

    /// The direct children of `id`, in fan-out order (e.g. `select!`/`join!`
    /// branch order). Empty if `id` is unknown or has no children.
    #[must_use]
    pub fn children(&self, id: TaskId) -> &[TaskId] {
        self.children.get(&id).map_or(&[], Vec::as_slice)
    }

    /// The total number of tasks in the tree.
    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether the tree has no tasks.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Flatten the tree into a pre-order traversal (parent before children,
    /// children in fan-out order) — this is the projection a DAP stack
    /// trace or a flat task list renders from, per the "tree, not a stack"
    /// rule: the tree is the source of truth, flattening is a view.
    #[must_use]
    pub fn flatten_preorder(&self) -> Vec<TaskId> {
        let mut out = Vec::with_capacity(self.nodes.len());
        for &root in &self.roots {
            self.push_preorder(root, &mut out);
        }
        out
    }

    fn push_preorder(&self, id: TaskId, out: &mut Vec<TaskId>) {
        out.push(id);
        for &child in self.children(id) {
            self.push_preorder(child, out);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{TaskKind, TaskState};

    fn node(id: u64, parent: Option<u64>) -> TaskNode {
        TaskNode {
            id: TaskId::new(id),
            name: format!("task-{id}"),
            kind: TaskKind::AsyncTask,
            state: TaskState::Runnable,
            parent: parent.map(TaskId::new),
        }
    }

    #[test]
    fn single_root_with_no_children() {
        let tree = TaskTree::try_from_nodes(vec![node(1, None)]).expect("valid tree");
        assert_eq!(tree.roots(), &[TaskId::new(1)]);
        assert!(tree.children(TaskId::new(1)).is_empty());
        assert_eq!(tree.len(), 1);
    }

    #[test]
    fn join_fan_out_becomes_ordered_children() {
        // A `join!(a, b)` shaped tree: one parent, two branches in order.
        let tree =
            TaskTree::try_from_nodes(vec![node(1, None), node(2, Some(1)), node(3, Some(1))])
                .expect("valid tree");

        assert_eq!(tree.roots(), &[TaskId::new(1)]);
        assert_eq!(
            tree.children(TaskId::new(1)),
            &[TaskId::new(2), TaskId::new(3)]
        );
        assert_eq!(
            tree.flatten_preorder(),
            vec![TaskId::new(1), TaskId::new(2), TaskId::new(3)]
        );
    }

    #[test]
    fn select_nested_branches_flatten_depth_first() {
        // select! branch 2 itself spawns a nested join! pair.
        let tree = TaskTree::try_from_nodes(vec![
            node(1, None),
            node(2, Some(1)),
            node(3, Some(1)),
            node(4, Some(3)),
            node(5, Some(3)),
        ])
        .expect("valid tree");

        assert_eq!(
            tree.flatten_preorder(),
            vec![
                TaskId::new(1),
                TaskId::new(2),
                TaskId::new(3),
                TaskId::new(4),
                TaskId::new(5)
            ]
        );
    }

    #[test]
    fn rejects_duplicate_ids() {
        let err = TaskTree::try_from_nodes(vec![node(1, None), node(1, None)])
            .expect_err("duplicate id must be rejected");
        assert!(matches!(err, DecoderError::InvalidTaskTree { .. }));
    }

    #[test]
    fn rejects_dangling_parent() {
        let err = TaskTree::try_from_nodes(vec![node(1, Some(99))])
            .expect_err("dangling parent must be rejected");
        assert!(matches!(err, DecoderError::InvalidTaskTree { .. }));
    }

    #[test]
    fn unknown_id_lookups_return_empty_or_none() {
        let tree = TaskTree::try_from_nodes(vec![node(1, None)]).expect("valid tree");
        assert!(tree.node(TaskId::new(404)).is_none());
        assert!(tree.children(TaskId::new(404)).is_empty());
    }

    #[test]
    fn empty_tree_is_empty() {
        let tree = TaskTree::try_from_nodes(vec![]).expect("valid tree");
        assert!(tree.is_empty());
        assert!(tree.flatten_preorder().is_empty());
    }
}
