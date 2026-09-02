import gleam/list


pub type GSet(a) {
  GSet(elements: List(a))
}

pub fn gset_new() -> GSet(a) {
  GSet(elements: [])
}

pub fn gset_add(set: GSet(a), element: a) -> GSet(a) {
  case list.contains(set.elements, element) {
    True -> set
    False -> GSet(elements: [element, ..set.elements])
  }
}

pub fn gset_contains(set: GSet(a), element: a) -> Bool {
  list.contains(set.elements, element)
}

pub fn gset_merge(set_a: GSet(a), set_b: GSet(a)) -> GSet(a) {
  let combined = list.append(set_a.elements, set_b.elements)
  GSet(elements: list.unique(combined))
}

pub fn gset_to_list(set: GSet(a)) -> List(a) {
  set.elements
}

pub type ElementTag {
  ElementTag(element: String, tag: String)
}

pub type ORSet {
  ORSet(
    add_set: List(ElementTag),
    remove_set: List(ElementTag),
  )
}

pub fn orset_new() -> ORSet {
  ORSet(add_set: [], remove_set: [])
}

pub fn orset_add(set: ORSet, element: String, tag: String) -> ORSet {
  let new_tag = ElementTag(element: element, tag: tag)
  ORSet(
    add_set: [new_tag, ..set.add_set],
    remove_set: set.remove_set,
  )
}

pub fn orset_remove(set: ORSet, element: String) -> ORSet {
  // Find all observed tags for this element in add_set
  let matching_tags =
    list.filter(set.add_set, fn(t) { t.element == element })

  ORSet(
    add_set: set.add_set,
    remove_set: list.append(matching_tags, set.remove_set),
  )
}

pub fn orset_contains(set: ORSet, element: String) -> Bool {
  let has_active_tag =
    list.any(set.add_set, fn(add_tag) {
      add_tag.element == element
      && !list.any(set.remove_set, fn(rem_tag) {
        rem_tag.element == add_tag.element && rem_tag.tag == add_tag.tag
      })
    })

  has_active_tag
}

pub fn orset_read(set: ORSet) -> List(String) {
  let active_elements =
    list.filter_map(set.add_set, fn(add_tag) {
      let is_removed =
        list.any(set.remove_set, fn(rem_tag) {
          rem_tag.element == add_tag.element && rem_tag.tag == add_tag.tag
        })

      case is_removed {
        True -> Error(Nil)
        False -> Ok(add_tag.element)
      }
    })

  list.unique(active_elements)
}

pub fn orset_merge(a: ORSet, b: ORSet) -> ORSet {
  let merged_add = list.unique(list.append(a.add_set, b.add_set))
  let merged_remove = list.unique(list.append(a.remove_set, b.remove_set))
  ORSet(add_set: merged_add, remove_set: merged_remove)
}
