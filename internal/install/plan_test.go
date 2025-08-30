package install

import "testing"

func TestTopoSortSimple(t *testing.T) {
    nodes := []string{"a", "b", "c", "d"}
    edges := map[string][]string{
        "a": {"b", "c"}, // a -> b, a -> c
        "b": {"d"},       // b -> d
        "c": {"d"},       // c -> d
    }
    indeg := map[string]int{"a": 0, "b": 1, "c": 1, "d": 2}
    order, err := topoSort(nodes, edges, indeg)
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    // valid orders start with a, end with d, b and c after a.
    if !(order[0] == "a" && order[len(order)-1] == "d") {
        t.Fatalf("unexpected order: %v", order)
    }
}

