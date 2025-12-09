import axios, { AxiosError, AxiosResponse } from 'axios';
import { GitHubRepository } from '../types';

// Custom error for GitHub API rate limiting
export class GitHubRateLimitError extends Error {
  public readonly resetAt: Date;
  public readonly remaining: number;

  constructor(message: string, resetAt: Date, remaining: number) {
    super(message);
    this.name = 'GitHubRateLimitError';
    this.resetAt = resetAt;
    this.remaining = remaining;
  }
}

// Custom error for GitHub API errors
export class GitHubAPIError extends Error {
  public readonly statusCode: number;

  constructor(message: string, statusCode: number) {
    super(message);
    this.name = 'GitHubAPIError';
    this.statusCode = statusCode;
  }
}

export class GitHubService {
  private baseURL = 'https://api.github.com';
  private readonly MAX_PAGES = 50; // Prevent infinite loops - max 5000 repos
  private readonly RATE_LIMIT_THRESHOLD = 10; // Stop if fewer than 10 requests remaining

  /**
   * Check rate limit headers and throw if approaching limit
   */
  private checkRateLimit(response: AxiosResponse): void {
    const remaining = parseInt(response.headers['x-ratelimit-remaining'] || '1000', 10);
    const resetTimestamp = parseInt(response.headers['x-ratelimit-reset'] || '0', 10);
    const resetAt = new Date(resetTimestamp * 1000);

    if (remaining <= this.RATE_LIMIT_THRESHOLD) {
      throw new GitHubRateLimitError(
        `GitHub API rate limit approaching. ${remaining} requests remaining. Resets at ${resetAt.toISOString()}`,
        resetAt,
        remaining
      );
    }
  }

  /**
   * Handle Axios errors and convert to appropriate custom errors
   */
  private handleAxiosError(error: AxiosError): never {
    if (error.response) {
      const status = error.response.status;

      // Check for rate limit error
      if (status === 403 || status === 429) {
        const remaining = parseInt(error.response.headers['x-ratelimit-remaining'] || '0', 10);
        const resetTimestamp = parseInt(error.response.headers['x-ratelimit-reset'] || '0', 10);

        if (remaining === 0 || status === 429) {
          throw new GitHubRateLimitError(
            'GitHub API rate limit exceeded',
            new Date(resetTimestamp * 1000),
            0
          );
        }
      }

      throw new GitHubAPIError(
        `GitHub API error: ${status} - ${(error.response.data as any)?.message || error.message}`,
        status
      );
    }

    throw error;
  }

  async getUserInfo(accessToken: string) {
    try {
      const response = await axios.get(`${this.baseURL}/user`, {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          Accept: 'application/vnd.github.v3+json',
        },
      });
      this.checkRateLimit(response);
      return response.data;
    } catch (error) {
      if (error instanceof AxiosError) {
        this.handleAxiosError(error);
      }
      throw error;
    }
  }

  async getUserRepositories(accessToken: string): Promise<GitHubRepository[]> {
    const repositories: GitHubRepository[] = [];
    let page = 1;
    const perPage = 100;

    try {
      while (page <= this.MAX_PAGES) {
        const response = await axios.get(`${this.baseURL}/user/repos`, {
          headers: {
            Authorization: `Bearer ${accessToken}`,
            Accept: 'application/vnd.github.v3+json',
          },
          params: {
            per_page: perPage,
            page,
            affiliation: 'owner,collaborator,organization_member',
          },
        });

        // Check rate limit before proceeding
        this.checkRateLimit(response);

        const repos = response.data;
        repositories.push(...repos);

        if (repos.length < perPage) break;
        page++;
      }

      return repositories;
    } catch (error) {
      if (error instanceof AxiosError) {
        this.handleAxiosError(error);
      }
      throw error;
    }
  }

  async checkRepositoryAccess(
    accessToken: string,
    owner: string,
    repo: string
  ): Promise<boolean> {
    try {
      const response = await axios.get(`${this.baseURL}/repos/${owner}/${repo}`, {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          Accept: 'application/vnd.github.v3+json',
        },
      });

      this.checkRateLimit(response);
      return response.status === 200;
    } catch (err) {
      if (err instanceof AxiosError) {
        // 404 or 403 without rate limit issue means no access
        if (err.response?.status === 404) {
          return false;
        }
        if (err.response?.status === 403) {
          const remaining = parseInt(err.response.headers['x-ratelimit-remaining'] || '1', 10);
          if (remaining > 0) {
            // Not a rate limit issue, just no permission
            return false;
          }
        }
        this.handleAxiosError(err);
      }
      throw err;
    }
  }

  async getAccessibleSubjects(accessToken: string): Promise<string[]> {
    const repos = await this.getUserRepositories(accessToken);
    return repos.map(repo => `webhooks.github.${repo.full_name.replace('/', '.')}`);
  }

  parseRepositoryFromWebhookPath(webhookPath: string): { owner: string; repo: string; source: string } | null {
    // /webhook/github/owner/repo -> { owner, repo, source }
    // /webhook/gitlab/owner/repo -> { owner, repo, source }
    const parts = webhookPath.split('/').filter(Boolean);

    if (parts.length < 4) {
      return null;
    }

    const [, source, owner, repo] = parts;
    return { source, owner, repo };
  }

  async checkWebhookAccess(
    accessToken: string,
    webhookPath: string
  ): Promise<boolean> {
    const repoInfo = this.parseRepositoryFromWebhookPath(webhookPath);

    if (!repoInfo) {
      return false;
    }

    // Currently only GitHub is supported
    if (repoInfo.source !== 'github') {
      return true;
    }

    return await this.checkRepositoryAccess(
      accessToken,
      repoInfo.owner,
      repoInfo.repo
    );
  }

  async exchangeCodeForToken(code: string, clientId: string, clientSecret: string) {
    const response = await axios.post(
      'https://github.com/login/oauth/access_token',
      {
        client_id: clientId,
        client_secret: clientSecret,
        code,
      },
      {
        headers: {
          Accept: 'application/json',
        },
      }
    );

    return response.data;
  }
}

export const githubService = new GitHubService();
