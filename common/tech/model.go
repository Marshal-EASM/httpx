package tech

type TechInfo struct {
	Company  string `yaml:"company"`
	Product  string `yaml:"product"`
	Lang     string `yaml:"lang"`
	Server   string `yaml:"server"`
	Category string `yaml:"category"`
}
type FingerPrint struct {
	Infos   string
	Matches []string
}
