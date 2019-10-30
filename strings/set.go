package strings

type Set map[string]struct{}

func MakeSet(a ...string) Set {
	set := make(Set, len(a))
	set.Add(a...)
	return set
}

func (set Set) ToSlice() []string {
	keys := make([]string, len(set))
	i := 0
	for k := range set {
		keys[i] = k
		i++
	}
	return keys
}

func (set Set) Add(a ...string) {
	for _, s := range a {
		set[s] = struct{}{}
	}
}

func (set Set) HasOneOf(a ...string) bool {
	if len(a) == 0 {
		return true
	}
	for _, s := range a {
		if _, ok := set[s]; ok {
			return true
		}
	}
	return false
}
