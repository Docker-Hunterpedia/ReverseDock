//! ReferenceGrant checks (`referencegrant_types.go`): a reference from an object in one
//! namespace to an object in another is allowed only when a ReferenceGrant **in the target's
//! namespace** lists the referrer's group, kind and namespace in `from` and the target's
//! group, kind and (optionally) name in `to`. A reference within one namespace needs no
//! grant. Grants are read on every translation, so deleting one revokes the access at once.

use crate::inventory::Inventory;

/// One side of a reference: group (`""` for the core group), kind and namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Referrer<'a> {
    /// API group.
    pub group: &'a str,
    /// Kind.
    pub kind: &'a str,
    /// Namespace.
    pub namespace: &'a str,
}

/// The target of a reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Target<'a> {
    /// API group (`""` for the core group).
    pub group: &'a str,
    /// Kind.
    pub kind: &'a str,
    /// Namespace.
    pub namespace: &'a str,
    /// Name.
    pub name: &'a str,
}

/// Whether `from` may refer to `to`.
#[must_use]
pub fn allowed(inventory: &Inventory, from: Referrer<'_>, to: Target<'_>) -> bool {
    if from.namespace == to.namespace {
        return true;
    }
    inventory
        .reference_grants
        .iter()
        .filter(|((namespace, _), _)| namespace == to.namespace)
        .any(|(_, grant)| {
            let from_ok = grant.spec.from.iter().any(|f| {
                f.group == from.group && f.kind == from.kind && f.namespace == from.namespace
            });
            let to_ok = grant.spec.to.iter().any(|t| {
                t.group == to.group
                    && t.kind == to.kind
                    && t.name.as_deref().is_none_or(|name| name == to.name)
            });
            from_ok && to_ok
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{ReferenceGrant, ReferenceGrantFrom, ReferenceGrantSpec, ReferenceGrantTo};

    fn grant(namespace: &str, from: ReferenceGrantFrom, to: ReferenceGrantTo) -> ReferenceGrant {
        let mut grant = ReferenceGrant::new(
            "g",
            ReferenceGrantSpec {
                from: vec![from],
                to: vec![to],
            },
        );
        grant.metadata.namespace = Some(namespace.to_owned());
        grant
    }

    fn inventory(grants: Vec<ReferenceGrant>) -> Inventory {
        let mut inventory = Inventory::default();
        for (i, g) in grants.into_iter().enumerate() {
            let ns = g.metadata.namespace.clone().unwrap_or_default();
            inventory.reference_grants.insert((ns, format!("g{i}")), g);
        }
        inventory
    }

    const ROUTE: Referrer<'static> = Referrer {
        group: "gateway.networking.k8s.io",
        kind: "HTTPRoute",
        namespace: "infra",
    };
    const SERVICE: Target<'static> = Target {
        group: "",
        kind: "Service",
        namespace: "web",
        name: "web-backend",
    };

    fn from(group: &str, kind: &str, namespace: &str) -> ReferenceGrantFrom {
        ReferenceGrantFrom {
            group: group.to_owned(),
            kind: kind.to_owned(),
            namespace: namespace.to_owned(),
        }
    }

    fn to(group: &str, kind: &str, name: Option<&str>) -> ReferenceGrantTo {
        ReferenceGrantTo {
            group: group.to_owned(),
            kind: kind.to_owned(),
            name: name.map(str::to_owned),
        }
    }

    #[test]
    fn same_namespace_needs_no_grant() {
        let target = Target {
            namespace: "infra",
            ..SERVICE
        };
        assert!(allowed(&Inventory::default(), ROUTE, target));
        assert!(!allowed(&Inventory::default(), ROUTE, SERVICE));
    }

    #[test]
    fn a_grant_must_match_every_field() {
        let good_from = from("gateway.networking.k8s.io", "HTTPRoute", "infra");
        let good_to = to("", "Service", Some("web-backend"));
        assert!(allowed(
            &inventory(vec![grant("web", good_from.clone(), good_to.clone())]),
            ROUTE,
            SERVICE
        ));
        // Every name of the kind.
        assert!(allowed(
            &inventory(vec![grant(
                "web",
                good_from.clone(),
                to("", "Service", None)
            )]),
            ROUTE,
            SERVICE
        ));
        // The cases of `httproute-invalid-reference-grant`.
        let wrong = [
            grant("infra", good_from.clone(), good_to.clone()),
            grant("web", from("other", "HTTPRoute", "infra"), good_to.clone()),
            grant(
                "web",
                from("gateway.networking.k8s.io", "Gateway", "infra"),
                good_to.clone(),
            ),
            grant(
                "web",
                from("gateway.networking.k8s.io", "HTTPRoute", "other"),
                good_to.clone(),
            ),
            grant(
                "web",
                good_from.clone(),
                to("other", "Service", Some("web-backend")),
            ),
            grant(
                "web",
                good_from.clone(),
                to("", "Secret", Some("web-backend")),
            ),
            grant("web", good_from, to("", "Service", Some("other"))),
        ];
        assert!(!allowed(&inventory(wrong.to_vec()), ROUTE, SERVICE));
    }
}
