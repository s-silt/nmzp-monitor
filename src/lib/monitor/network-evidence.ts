/** Frontend parse of public network/endpoint evidence. Reuses core strict parsers. */

export {
  ossHostShape,
  parseEndpointList,
  parseNetworkSampleReport,
  publicNetworkHistory,
  publicNetworkSample,
  sanitizeAuditText,
} from "../../../core/network-evidence.ts";
export type {
  EndpointEvidence,
  NetworkConnection,
  NetworkHistoryRow,
  NetworkSampleReport,
} from "../../../core/schema.ts";
