use std::collections::{BTreeSet, HashMap, HashSet};

use crate::error::ExecutionError;
use crate::schema_control::SchemaObject;

pub fn topological_sort(objects: Vec<SchemaObject>) -> Result<Vec<SchemaObject>, ExecutionError> {
    let object_names: Vec<&str> = objects
        .iter()
        .map(|object| object.object_name.as_str())
        .collect();
    let sorted_indexes = topological_indexes(
        object_names.len(),
        |index| object_names[index],
        |index| objects[index].depends_on.iter().map(String::as_str),
    )?;

    let mut indexed: Vec<Option<SchemaObject>> = objects.into_iter().map(Some).collect();
    Ok(sorted_indexes
        .into_iter()
        .map(|index| indexed[index].take().expect("sorted index exists"))
        .collect())
}

pub fn find_dependency_cycle<'a, F, D>(
    count: usize,
    object_name: F,
    dependencies: D,
) -> Option<Vec<String>>
where
    F: Fn(usize) -> &'a str,
    D: Fn(usize) -> Vec<&'a str>,
{
    match topological_index_result(count, &object_name, |index| dependencies(index).into_iter()) {
        Ok(_) => None,
        Err(cycle) => Some(
            cycle
                .into_iter()
                .map(|index| object_name(index).to_string())
                .collect(),
        ),
    }
}

fn topological_indexes<'a, F, I>(
    count: usize,
    object_name: F,
    dependencies: impl Fn(usize) -> I,
) -> Result<Vec<usize>, ExecutionError>
where
    F: Fn(usize) -> &'a str,
    I: Iterator<Item = &'a str>,
{
    topological_index_result(count, &object_name, dependencies).map_err(|cycle| {
        let cycle = cycle.into_iter().map(&object_name).collect::<Vec<_>>();
        ExecutionError::apply(format!(
            "dependency cycle detected among: {}",
            cycle.join(", ")
        ))
    })
}

fn topological_index_result<'a, F, I>(
    count: usize,
    object_name: &F,
    dependencies: impl Fn(usize) -> I,
) -> Result<Vec<usize>, Vec<usize>>
where
    F: Fn(usize) -> &'a str,
    I: Iterator<Item = &'a str>,
{
    let name_to_idx: HashMap<&str, usize> = (0..count)
        .map(|index| (object_name(index), index))
        .collect();
    let mut in_degree = vec![0usize; count];
    let mut adjacency: Vec<Vec<usize>> = vec![Vec::new(); count];

    for index in 0..count {
        for dep in dependencies(index) {
            if let Some(&dep_index) = name_to_idx.get(dep) {
                adjacency[dep_index].push(index);
                in_degree[index] += 1;
            }
        }
    }

    let mut available: BTreeSet<usize> = in_degree
        .iter()
        .enumerate()
        .filter(|(_, degree)| **degree == 0)
        .map(|(index, _)| index)
        .collect();

    let mut sorted = Vec::with_capacity(count);
    while let Some(index) = available.pop_first() {
        sorted.push(index);
        for &dependent in &adjacency[index] {
            in_degree[dependent] -= 1;
            if in_degree[dependent] == 0 {
                available.insert(dependent);
            }
        }
    }

    if sorted.len() != count {
        let sorted_set: HashSet<usize> = sorted.iter().copied().collect();
        return Err((0..count)
            .filter(|index| !sorted_set.contains(index))
            .collect::<Vec<_>>());
    }

    Ok(sorted)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object(name: &str, depends_on: &[&str]) -> SchemaObject {
        SchemaObject {
            kind: "table".to_string(),
            object_name: name.to_string(),
            source_file: format!("tables/{name}.sql"),
            depends_on: depends_on.iter().map(|dep| dep.to_string()).collect(),
            rollback_file: None,
            transactional: true,
            raw_sql: format!("create table if not exists {name}(id int);"),
            canonical_sql: format!("create table if not exists {name}(id int);"),
            sha256: name.to_string(),
        }
    }

    #[test]
    fn sorts_linear_chain_dependencies_first() {
        let sorted = topological_sort(vec![
            object("c", &["b"]),
            object("a", &[]),
            object("b", &["a"]),
        ])
        .expect("sort");
        let names: Vec<_> = sorted
            .iter()
            .map(|object| object.object_name.as_str())
            .collect();

        assert_eq!(names, vec!["a", "b", "c"]);
    }

    #[test]
    fn ignores_unknown_external_dependencies() {
        let sorted = topological_sort(vec![object("a", &["pgvector extension"]), object("b", &[])])
            .expect("sort");
        let names: Vec<_> = sorted
            .iter()
            .map(|object| object.object_name.as_str())
            .collect();

        assert_eq!(names, vec!["a", "b"]);
    }

    #[test]
    fn preserves_source_order_when_dependency_becomes_available() {
        let sorted = topological_sort(vec![
            object("view", &[]),
            object("materialized_view", &["view"]),
            object("cron_job", &[]),
        ])
        .expect("sort");
        let names: Vec<_> = sorted
            .iter()
            .map(|object| object.object_name.as_str())
            .collect();

        assert_eq!(names, vec!["view", "materialized_view", "cron_job"]);
    }

    #[test]
    fn reports_cycle_members() {
        let error = topological_sort(vec![
            object("a", &["c"]),
            object("b", &["a"]),
            object("c", &["b"]),
        ])
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("dependency cycle detected among: a, b, c"));
    }
}
