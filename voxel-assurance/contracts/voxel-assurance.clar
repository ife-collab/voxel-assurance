;; VoxelAssurance Quality Assurance Platform

;; This contract manages product quality records, IoT threshold enforcement,
;; and compliance tracking on-chain. Products are registered with a quality
;; fingerprint and can inherit attributes from parent materials.

;; ============================================================
;; CONSTANTS
;; ============================================================

(define-constant CONTRACT-OWNER tx-sender)

(define-constant ERR-NOT-AUTHORIZED        (err u100))
(define-constant ERR-PRODUCT-NOT-FOUND     (err u101))
(define-constant ERR-PRODUCT-EXISTS        (err u102))
(define-constant ERR-INVALID-QUALITY       (err u103))
(define-constant ERR-THRESHOLD-BREACHED    (err u104))
(define-constant ERR-INVALID-STAKE         (err u105))
(define-constant ERR-ORACLE-NOT-FOUND      (err u106))
(define-constant ERR-PARENT-NOT-FOUND      (err u107))

;; Quality score range: 0 (worst) to 1000 (best)
(define-constant MAX-QUALITY-SCORE u1000)
(define-constant MIN-QUALITY-SCORE u0)

;; ============================================================
;; DATA MAPS AND VARS
;; ============================================================

;; Tracks the next product ID
(define-data-var next-product-id uint u1)

;; Tracks the next compliance oracle ID
(define-data-var next-oracle-id uint u1)

;; Product registry
;; product-id -> product data
(define-map products
  { product-id: uint }
  {
    owner:            principal,
    name:             (string-ascii 64),
    category:         (string-ascii 32),
    ;; Quality fingerprint: a u256-range hash represented as uint
    quality-fingerprint: uint,
    ;; Current quality score 0-1000
    quality-score:    uint,
    ;; Optional parent product (for quality inheritance)
    parent-id:        (optional uint),
    ;; Environmental snapshot: temperature (x10 for 1 decimal), humidity (x10)
    temperature:      int,
    humidity:         uint,
    ;; Compliance status: "compliant", "warning", "breached"
    compliance-status: (string-ascii 16),
    registered-at:    uint,
    updated-at:       uint,
    active:           bool
  }
)

;; Quality event log per product
;; { product-id, event-index } -> event data
(define-map quality-events
  { product-id: uint, event-index: uint }
  {
    quality-score:  uint,
    temperature:    int,
    humidity:       uint,
    reported-by:    principal,
    block-height:   uint,
    note:           (string-ascii 128)
  }
)

;; Tracks how many events each product has
(define-map product-event-count
  { product-id: uint }
  { count: uint }
)

;; Compliance oracles: define acceptable quality thresholds per category
(define-map compliance-oracles
  { oracle-id: uint }
  {
    category:          (string-ascii 32),
    min-quality-score: uint,
    max-temperature:   int,
    min-humidity:      uint,
    max-humidity:      uint,
    jurisdiction:      (string-ascii 32),
    active:            bool
  }
)

;; Fractional quality stake: principal -> product-id -> stake amount (in microSTX)
(define-map quality-stakes
  { staker: principal, product-id: uint }
  { amount: uint }
)

;; Approved IoT reporters (addresses allowed to submit sensor readings)
(define-map approved-reporters
  { reporter: principal }
  { approved: bool }
)

;; ============================================================
;; PRIVATE HELPERS
;; ============================================================

;; Clamp a uint between min and max
(define-private (clamp-quality (score uint))
  (if (> score MAX-QUALITY-SCORE)
    MAX-QUALITY-SCORE
    score)
)

;; Derive inherited quality from parent (average of parent + own score)
(define-private (inherit-quality (parent-score uint) (own-score uint))
  (/ (+ parent-score own-score) u2)
)

;; Determine compliance status string based on score and oracle thresholds
(define-private (derive-compliance-status (score uint) (min-score uint))
  (if (>= score min-score)
    "compliant"
    (if (>= score (/ (* min-score u8) u10))
      "warning"
      "breached"))
)

;; Check whether an oracle threshold is satisfied for a given reading
(define-private (oracle-check
    (oracle-id uint)
    (quality-score uint)
    (temperature int)
    (humidity uint))
  (match (map-get? compliance-oracles { oracle-id: oracle-id })
    oracle (and
              (>= quality-score (get min-quality-score oracle))
              (<= temperature   (get max-temperature oracle))
              (>= humidity      (get min-humidity oracle))
              (<= humidity      (get max-humidity oracle)))
    false)
)

;; ============================================================
;; ADMINISTRATIVE FUNCTIONS
;; ============================================================

;; Approve or revoke an IoT reporter
(define-public (set-reporter-approval (reporter principal) (approved bool))
  (begin
    (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-NOT-AUTHORIZED)
    (map-set approved-reporters { reporter: reporter } { approved: approved })
    (ok true))
)

;; Register a compliance oracle for a product category
(define-public (register-oracle
    (category         (string-ascii 32))
    (min-quality      uint)
    (max-temperature  int)
    (min-humidity     uint)
    (max-humidity     uint)
    (jurisdiction     (string-ascii 32)))
  (let ((oracle-id (var-get next-oracle-id)))
    (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-NOT-AUTHORIZED)
    (map-set compliance-oracles
      { oracle-id: oracle-id }
      {
        category:          category,
        min-quality-score: min-quality,
        max-temperature:   max-temperature,
        min-humidity:      min-humidity,
        max-humidity:      max-humidity,
        jurisdiction:      jurisdiction,
        active:            true
      })
    (var-set next-oracle-id (+ oracle-id u1))
    (ok oracle-id))
)

;; Deactivate an oracle (e.g., regulation change)
(define-public (deactivate-oracle (oracle-id uint))
  (let ((oracle (unwrap! (map-get? compliance-oracles { oracle-id: oracle-id }) ERR-ORACLE-NOT-FOUND)))
    (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-NOT-AUTHORIZED)
    (map-set compliance-oracles { oracle-id: oracle-id }
      (merge oracle { active: false }))
    (ok true))
)

;; ============================================================
;; PRODUCT REGISTRATION
;; ============================================================

;; Register a new product on-chain
;; parent-id: pass (some parent-product-id) to enable quality inheritance, or none
(define-public (register-product
    (name               (string-ascii 64))
    (category           (string-ascii 32))
    (quality-fingerprint uint)
    (initial-quality    uint)
    (parent-id          (optional uint))
    (temperature        int)
    (humidity           uint))
  (let (
    (product-id (var-get next-product-id))
    (safe-score (clamp-quality initial-quality))
    ;; If a parent exists, average quality scores
    (effective-score
      (match parent-id
        pid (match (map-get? products { product-id: pid })
              parent (inherit-quality (get quality-score parent) safe-score)
              safe-score)
        safe-score))
  )
    (map-set products
      { product-id: product-id }
      {
        owner:               tx-sender,
        name:                name,
        category:            category,
        quality-fingerprint: quality-fingerprint,
        quality-score:       effective-score,
        parent-id:           parent-id,
        temperature:         temperature,
        humidity:            humidity,
        compliance-status:   "compliant",
        registered-at:       block-height,
        updated-at:          block-height,
        active:              true
      })
    (map-set product-event-count { product-id: product-id } { count: u0 })
    (var-set next-product-id (+ product-id u1))
    (ok product-id))
)

;; ============================================================
;; IOT SENSOR / QUALITY REPORTING
;; ============================================================

;; Submit a new quality reading for a product.
;; Any approved reporter may call this.
;; Automatically evaluates oracle thresholds and updates compliance status.
(define-public (submit-quality-reading
    (product-id    uint)
    (quality-score uint)
    (temperature   int)
    (humidity      uint)
    (oracle-id     uint)
    (note          (string-ascii 128)))
  (let (
    (reporter tx-sender)
    (product  (unwrap! (map-get? products { product-id: product-id }) ERR-PRODUCT-NOT-FOUND))
    (reporter-entry (default-to { approved: false }
                      (map-get? approved-reporters { reporter: reporter })))
    (oracle   (unwrap! (map-get? compliance-oracles { oracle-id: oracle-id }) ERR-ORACLE-NOT-FOUND))
    (safe-score (clamp-quality quality-score))
    (compliant  (oracle-check oracle-id safe-score temperature humidity))
    (status     (derive-compliance-status safe-score (get min-quality-score oracle)))
    (event-count (get count (default-to { count: u0 }
                    (map-get? product-event-count { product-id: product-id }))))
  )
    ;; Only owner or approved reporters may submit
    (asserts!
      (or (is-eq reporter (get owner product))
          (get approved reporter-entry))
      ERR-NOT-AUTHORIZED)

    ;; Update product with latest reading
    (map-set products { product-id: product-id }
      (merge product {
        quality-score:     safe-score,
        temperature:       temperature,
        humidity:          humidity,
        compliance-status: status,
        updated-at:        block-height
      }))

    ;; Append event to quality history
    (map-set quality-events
      { product-id: product-id, event-index: event-count }
      {
        quality-score: safe-score,
        temperature:   temperature,
        humidity:      humidity,
        reported-by:   reporter,
        block-height:  block-height,
        note:          note
      })
    (map-set product-event-count { product-id: product-id }
      { count: (+ event-count u1) })

    ;; Return threshold breach error so callers can react via smart contract logic
    (if compliant
      (ok status)
      ERR-THRESHOLD-BREACHED))
)

;; ============================================================
;; FRACTIONAL QUALITY STAKES
;; ============================================================

;; Stake STX against a product's quality (aligns incentives for quality maintenance)
(define-public (stake-on-quality (product-id uint) (amount uint))
  (let (
    (_product (unwrap! (map-get? products { product-id: product-id }) ERR-PRODUCT-NOT-FOUND))
    (existing (get amount (default-to { amount: u0 }
                (map-get? quality-stakes { staker: tx-sender, product-id: product-id }))))
  )
    (asserts! (> amount u0) ERR-INVALID-STAKE)
    (try! (stx-transfer? amount tx-sender (as-contract tx-sender)))
    (map-set quality-stakes
      { staker: tx-sender, product-id: product-id }
      { amount: (+ existing amount) })
    (ok true))
)

;; Withdraw a stake (only if product is still compliant)
(define-public (withdraw-stake (product-id uint))
  (let (
    (product (unwrap! (map-get? products { product-id: product-id }) ERR-PRODUCT-NOT-FOUND))
    (stake   (unwrap! (map-get? quality-stakes { staker: tx-sender, product-id: product-id })
               ERR-INVALID-STAKE))
    (amount  (get amount stake))
  )
    ;; Only allow full withdrawal when product is compliant
    (asserts! (is-eq (get compliance-status product) "compliant") ERR-THRESHOLD-BREACHED)
    (asserts! (> amount u0) ERR-INVALID-STAKE)
    (map-set quality-stakes { staker: tx-sender, product-id: product-id } { amount: u0 })
    (as-contract (stx-transfer? amount tx-sender tx-sender))
  )
)

;; ============================================================
;; READ-ONLY FUNCTIONS
;; ============================================================

;; Get full product details
(define-read-only (get-product (product-id uint))
  (map-get? products { product-id: product-id })
)

;; Get a specific quality event from a product's history
(define-read-only (get-quality-event (product-id uint) (event-index uint))
  (map-get? quality-events { product-id: product-id, event-index: event-index })
)

;; Get the total number of quality events for a product
(define-read-only (get-event-count (product-id uint))
  (get count (default-to { count: u0 }
    (map-get? product-event-count { product-id: product-id })))
)

;; Get a compliance oracle's configuration
(define-read-only (get-oracle (oracle-id uint))
  (map-get? compliance-oracles { oracle-id: oracle-id })
)

;; Get stake amount for a staker on a product
(define-read-only (get-stake (staker principal) (product-id uint))
  (get amount (default-to { amount: u0 }
    (map-get? quality-stakes { staker: staker, product-id: product-id })))
)

;; Check if a reporter is approved
(define-read-only (is-reporter-approved (reporter principal))
  (get approved (default-to { approved: false }
    (map-get? approved-reporters { reporter: reporter })))
)

;; Get the current compliance status of a product
(define-read-only (get-compliance-status (product-id uint))
  (match (map-get? products { product-id: product-id })
    product (some (get compliance-status product))
    none)
)

;; Simulate oracle validation without writing state (for off-chain preview)
(define-read-only (preview-oracle-check
    (oracle-id     uint)
    (quality-score uint)
    (temperature   int)
    (humidity      uint))
  (oracle-check oracle-id quality-score temperature humidity)
)

;; Get next available product ID
(define-read-only (get-next-product-id)
  (var-get next-product-id)
)

;; Get next available oracle ID
(define-read-only (get-next-oracle-id)
  (var-get next-oracle-id)
)
