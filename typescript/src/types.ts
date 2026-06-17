export type ContentSource =
  | 'user'
  | 'file'
  | 'mcp_tool'
  | 'web_search'
  | 'web_fetch'
  | 'clipboard'
  | 'unknown';

export const SOURCE_TRUST: Record<ContentSource, number> = {
  user: 1.0,
  file: 0.9,
  mcp_tool: 0.5,
  web_search: 0.2,
  web_fetch: 0.2,
  clipboard: 0.1,
  unknown: 0.3,
};

export type RiskCategory =
  | 'governing_parameter'
  | 'urgency'
  | 'prescriptive'
  | 'authority'
  | 'structural';

export interface RiskFactor {
  category: RiskCategory;
  matches: string[];
  weight: number;
  description: string;
}

export interface AssessmentInput {
  content: string;
  source: ContentSource;
  intendedAction?: string;
}

export interface AletheiaAssessment {
  injectionRiskScore: number;
  riskFactors: RiskFactor[];
  governingParameters: string[];
  recommendation: 'proceed' | 'verify' | 'stop';
  reasoning: string;
  verificationSteps?: string[];
}
