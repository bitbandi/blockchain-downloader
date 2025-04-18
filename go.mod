module blockchain-downloader

go 1.21

require (
	github.com/btcsuite/btcd v0.23.4
	github.com/btcsuite/btcd/chaincfg/chainhash v1.1.0
)

require (
	golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9 // indirect
	golang.org/x/sys v0.0.0-20200814200057-3d37ad5750ed // indirect
)

replace github.com/btcsuite/btcd => github.com/bitbandi/btcd v0.0.0-20231211175150-424d994afec6
