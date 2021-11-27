package bech32

type ChecksumConst int

const (
	Version0Const ChecksumConst = 1

	VersionMConst ChecksumConst = 0x2bc830a3
)

type Version uint8

const (
	Version0 Version = iota

	VersionM

	VersionUnknown
)

var VersionToConsts = map[Version]ChecksumConst{
	Version0: Version0Const,
	VersionM: VersionMConst,
}

var ConstsToVersion = map[ChecksumConst]Version{
	Version0Const: Version0,
	VersionMConst: VersionM,
}
