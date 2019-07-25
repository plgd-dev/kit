package strings

func SliceContains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// ToSlice converts a string or []string.
func ToSlice(v interface{}) []string {
	if v == nil {
		return nil
	}
	s, ok := v.(string)
	if ok && s == "" {
		return nil
	}
	if ok {
		return []string{s}
	}
	if a, ok := v.([]string); ok {
		return a
	}
	a, ok := v.([]interface{})
	if !ok {
		return nil
	}
	o := make([]string, len(a))
	i := 0
	for _, e := range a {
		s, ok := e.(string)
		if !ok {
			return nil
		}
		o[i] = s
		i++
	}
	return o
}
