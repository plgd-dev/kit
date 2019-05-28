package string

type StringSet map[string]struct{}

func MakeStringSet(a ...string) StringSet {
	set := make(StringSet, len(a))
	set.Add(a...)
	return set
}

func (set StringSet) ToSlice() []string {
	keys := make([]string, len(set))
	i := 0
	for k := range set {
		keys[i] = k
		i++
	}
	return keys
}

func (set StringSet) Add(a ...string) {
	for _, s := range a {
		set[s] = struct{}{}
	}
}

func (set StringSet) HasOneOf(a ...string) bool {
	for _, s := range a {
		if _, ok := set[s]; ok {
			return true
		}
	}
	return false
}
