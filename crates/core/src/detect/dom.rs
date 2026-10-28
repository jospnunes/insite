//! Selector matching over the extracted element index, without a DOM.

use std::collections::HashMap;

use insite_sigc::selector::{Combinator, Complex, Compound, SelectorList};

use crate::extract::Element;

/// The elements of a page, indexed so a selector only looks at candidates for its
/// rightmost compound (by id, then class, then tag).
pub struct ElementIndex<'a> {
    elements: &'a [Element],
    by_id: HashMap<&'a str, Vec<usize>>,
    by_class: HashMap<&'a str, Vec<usize>>,
    by_tag: HashMap<&'a str, Vec<usize>>,
    /// Element properties read by the browser, keyed by element position.
    properties: HashMap<(usize, String), String>,
}

impl<'a> ElementIndex<'a> {
    pub fn new(elements: &'a [Element]) -> Self {
        let mut index = ElementIndex {
            elements,
            by_id: HashMap::new(),
            by_class: HashMap::new(),
            by_tag: HashMap::new(),
            properties: HashMap::new(),
        };
        for (i, element) in elements.iter().enumerate() {
            index.by_tag.entry(element.tag.as_str()).or_default().push(i);
            for (name, value) in &element.attrs {
                match name.as_str() {
                    "id" => index.by_id.entry(value.as_str()).or_default().push(i),
                    "class" => {
                        for class in value.split_ascii_whitespace() {
                            index.by_class.entry(class).or_default().push(i);
                        }
                    }
                    _ => {}
                }
            }
        }
        index
    }

    pub fn with_properties(mut self, properties: HashMap<(usize, String), String>) -> Self {
        self.properties = properties;
        self
    }

    pub fn property(&self, element: &Element, name: &str) -> Option<String> {
        let position = self.elements.iter().position(|e| std::ptr::eq(e, element))?;
        self.properties.get(&(position, name.to_owned())).cloned()
    }

    /// Elements matching any selector of the list, in document order.
    pub fn select(&self, list: &SelectorList) -> Vec<&'a Element> {
        let mut found: Vec<usize> = Vec::new();
        for complex in &list.0 {
            let Some((_, last)) = complex.0.last() else { continue };
            for i in self.candidates(last) {
                if self.matches_complex(complex, complex.0.len() - 1, i) {
                    found.push(i);
                }
            }
        }
        found.sort_unstable();
        found.dedup();
        found.into_iter().map(|i| &self.elements[i]).collect()
    }

    fn candidates(&self, compound: &Compound) -> Vec<usize> {
        let all = || (0..self.elements.len()).collect();
        if let Some(id) = &compound.id {
            return self.by_id.get(id.as_str()).cloned().unwrap_or_default();
        }
        if let Some(class) = compound.classes.first() {
            return self.by_class.get(class.as_str()).cloned().unwrap_or_default();
        }
        if let Some(tag) = &compound.tag {
            return self.by_tag.get(tag.as_str()).cloned().unwrap_or_default();
        }
        all()
    }

    /// Whether element `i` matches compound `at` of `complex` and, through the
    /// combinators, everything to its left. Descendant combinators backtrack over
    /// every ancestor, so `a b c` is right even when the nearest `b` fails.
    fn matches_complex(&self, complex: &Complex, at: usize, i: usize) -> bool {
        let (combinator, compound) = &complex.0[at];
        if !matches_compound(compound, &self.elements[i]) {
            return false;
        }
        if at == 0 {
            return true;
        }
        let mut parent = self.elements[i].parent;
        match combinator {
            Combinator::Child => parent.is_some_and(|p| self.matches_complex(complex, at - 1, p)),
            Combinator::Descendant => {
                while let Some(p) = parent {
                    if self.matches_complex(complex, at - 1, p) {
                        return true;
                    }
                    parent = self.elements[p].parent;
                }
                false
            }
        }
    }
}

fn matches_compound(compound: &Compound, element: &Element) -> bool {
    if compound.tag.as_ref().is_some_and(|t| *t != element.tag) {
        return false;
    }
    if let Some(id) = &compound.id
        && element.attr("id") != Some(id.as_str())
    {
        return false;
    }
    if !compound.classes.is_empty() {
        let classes: Vec<&str> = element
            .attr("class")
            .unwrap_or_default()
            .split_ascii_whitespace()
            .collect();
        if !compound.classes.iter().all(|c| classes.contains(&c.as_str())) {
            return false;
        }
    }
    compound
        .attrs
        .iter()
        .all(|a| element.attr(&a.name).is_some_and(|v| a.matches(v)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use insite_sigc::selector::parse;

    fn el(tag: &str, attrs: &[(&str, &str)], parent: Option<usize>) -> Element {
        Element {
            tag: tag.into(),
            attrs: attrs.iter().map(|(n, v)| (n.to_string(), v.to_string())).collect(),
            parent,
            text: String::new(),
        }
    }

    fn page() -> Vec<Element> {
        vec![
            el("html", &[], None),
            el("body", &[("class", "home shop")], Some(0)),
            el("div", &[("id", "app"), ("class", "wrapper")], Some(1)),
            el("section", &[("class", "shopify-section")], Some(2)),
            el("script", &[("src", "/wp-content/themes/x.js")], Some(3)),
            el("div", &[("class", "wrapper inner")], Some(1)),
        ]
    }

    fn tags(index: &ElementIndex, selector: &str) -> Vec<String> {
        index
            .select(&parse(selector).unwrap())
            .iter()
            .map(|e| e.tag.clone())
            .collect()
    }

    #[test]
    fn compounds_and_combinators() {
        let elements = page();
        let index = ElementIndex::new(&elements);
        assert_eq!(tags(&index, "#app"), ["div"]);
        assert_eq!(tags(&index, "div.wrapper"), ["div", "div"]);
        assert_eq!(tags(&index, "div.wrapper.inner"), ["div"]);
        assert_eq!(tags(&index, "body.shop script[src*='wp-content']"), ["script"]);
        assert_eq!(tags(&index, "#app > section"), ["section"]);
        assert!(tags(&index, "body > section").is_empty());
        assert_eq!(tags(&index, "html div section, .nothing"), ["section"]);
    }

    #[test]
    fn descendant_matching_backtracks() {
        // `div div script`: the nearest div ancestor (#app) has no div above it,
        // but there is none either way; check a case where the second-nearest works.
        let elements = vec![
            el("div", &[("class", "outer")], None),
            el("div", &[("class", "mid")], Some(0)),
            el("span", &[], Some(1)),
            el("script", &[], Some(2)),
        ];
        let index = ElementIndex::new(&elements);
        assert_eq!(tags(&index, "div.outer span script"), ["script"]);
        assert_eq!(tags(&index, ".outer .mid > span > script"), ["script"]);
    }
}
