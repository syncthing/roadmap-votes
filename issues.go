package main

import (
	"context"
	"log"
	"sort"
	"sync"
	"time"

	"github.com/google/go-github/v32/github"
	"golang.org/x/oauth2"
)

const (
	issueCacheTime = time.Hour
)

type cachedIssueList struct {
	mut                sync.Mutex
	refreshed          time.Time
	owner, repo, token string
	issues             []*github.Issue
	votes              map[int][]vote
}

type vote struct {
	id   int64 // for deleting
	user string
}

func newCachedIssueList(owner, repo, token string) *cachedIssueList {
	l := &cachedIssueList{
		owner: owner,
		repo:  repo,
		token: token,
	}

	// Periodically refresh issues
	go func() {
		for {
			l.Issues()
			time.Sleep(issueCacheTime)
		}
	}()

	return l
}

// Issues returns the list of issues, sorted by current number of votes
func (l *cachedIssueList) Issues() []*github.Issue {
	l.mut.Lock()
	defer l.mut.Unlock()

	if l.issues == nil || l.refreshed.Before(time.Now().Add(-issueCacheTime)) {
		issues, err := l.loadIssues(context.Background())
		if err != nil {
			log.Println("Failed to load issues:", err)
		} else {
			l.issues = issues
			l.votes = make(map[int][]vote)
			l.refreshed = time.Now()
		}
	}

	sort.Slice(l.issues, func(a, b int) bool {
		avotes := len(l.issueVotesLocked(l.issues[a].GetNumber()))
		bvotes := len(l.issueVotesLocked(l.issues[b].GetNumber()))
		if users, ok := l.votes[l.issues[b].GetNumber()]; ok {
			bvotes = len(users)
		}
		if avotes != bvotes {
			// More votes higher up
			return avotes > bvotes
		}
		// New issues higher up
		return l.issues[a].GetNumber() > l.issues[b].GetNumber()
	})

	return l.issues
}

// Votes returns the number of votes for the given issue number
func (l *cachedIssueList) Votes(issue int) int {
	l.mut.Lock()
	defer l.mut.Unlock()

	return len(l.issueVotesLocked(issue))
}

// UserHasVoted returns true if the user has voted for this issue
func (l *cachedIssueList) UserHasVoted(issue int, user string) bool {
	_, ok := l.userVoteID(issue, user)
	return ok
}

// userVoteID returns the ID of the vote the user has cast on this issue, if
// any. (This is usable as input to deleting the vote.)
func (l *cachedIssueList) userVoteID(issue int, user string) (int64, bool) {
	l.mut.Lock()
	defer l.mut.Unlock()

	votes := l.issueVotesLocked(issue)
	i := sort.Search(len(votes), func(i int) bool { return votes[i].user >= user })
	if i >= len(votes) || votes[i].user != user {
		return 0, false
	}
	return votes[i].id, true
}

// issueVotesLocked returns the list of votes for the issue, loading them
// from GitHub if necessary.
func (l *cachedIssueList) issueVotesLocked(issue int) []vote {
	votes, ok := l.votes[issue]
	if !ok {
		var err error
		if votes, err = l.loadVotes(context.Background(), issue); err == nil {
			l.votes[issue] = votes
		}
	}
	return votes
}

// flushVotes removes the cached list of votes for an issue
func (l *cachedIssueList) flushVotes(issue int) {
	l.mut.Lock()
	defer l.mut.Unlock()
	delete(l.votes, issue)
}

// loadIssue loads issues from GitHub
func (l *cachedIssueList) loadIssues(ctx context.Context) ([]*github.Issue, error) {
	client := github.NewClient(oauth2.NewClient(ctx, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: l.token})))
	var issues []*github.Issue
	opts := &github.IssueListByRepoOptions{
		State:  "open",
		Labels: []string{"enhancement"},
	}
	for {
		iss, resp, err := client.Issues.ListByRepo(ctx, l.owner, l.repo, opts)
		if err != nil {
			return nil, err
		}
		issues = append(issues, iss...)
		if resp.NextPage <= opts.Page {
			break
		}
		opts.Page = resp.NextPage
	}

	return issues, nil
}

// loadVotes loads the set of votes for an issue from GitHub
func (l *cachedIssueList) loadVotes(ctx context.Context, issue int) ([]vote, error) {
	client := github.NewClient(oauth2.NewClient(ctx, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: l.token})))
	opts := &github.ListOptions{}
	var reactions []*github.Reaction
	for {
		rss, resp, err := client.Reactions.ListIssueReactions(ctx, l.owner, l.repo, issue, opts)
		if err != nil {
			return nil, err
		}
		reactions = append(reactions, rss...)
		if resp.NextPage <= opts.Page {
			break
		}
		opts.Page = resp.NextPage
	}

	plusOnes := make([]vote, 0, len(reactions))
	for _, r := range reactions {
		if r.GetContent() != "+1" {
			continue
		}
		plusOnes = append(plusOnes, vote{user: r.User.GetLogin(), id: r.GetID()})
	}

	sort.Slice(plusOnes, func(a, b int) bool {
		return plusOnes[a].user < plusOnes[b].user
	})

	return plusOnes, nil
}
