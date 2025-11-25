import axios from 'axios';
import { GitHubRepository } from '../types';

export class GitHubService {
  private baseURL = 'https://api.github.com';

  async getUserInfo(accessToken: string) {
    const response = await axios.get(`${this.baseURL}/user`, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: 'application/vnd.github.v3+json',
      },
    });
    return response.data;
  }

  async getUserRepositories(accessToken: string): Promise<GitHubRepository[]> {
    const repositories: GitHubRepository[] = [];
    let page = 1;
    const perPage = 100;

    while (true) {
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

      const repos = response.data;
      repositories.push(...repos);

      if (repos.length < perPage) break;
      page++;
    }

    return repositories;
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

      return response.status === 200;
    } catch (err: any) {
      if (err.response?.status === 404 || err.response?.status === 403) {
        return false;
      }
      throw err;
    }
  }

  async getAccessibleSubjects(accessToken: string): Promise<string[]> {
    const repos = await this.getUserRepositories(accessToken);
    return repos.map(repo => `webhooks.github.${repo.full_name.replace('/', '.')}`);
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
