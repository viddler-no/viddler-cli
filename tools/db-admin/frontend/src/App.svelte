<script>
	import { onMount } from 'svelte';
	import Explorer from './Explorer.svelte';
	import QueryInput from './QueryInput.svelte';
	import QueryResult from './QueryResult.svelte';

	let structure = null;
	let queryResult = null;

	onMount(async () => {
		const res = await fetch('/structure');
		structure = await res.json();
		console.log(structure);
	});

	async function doQuery(event) {
		let query = event.detail.query;
		console.log(query);
		const res = await fetch('/query', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json'
			},
			body: JSON.stringify({
				query
			})
		});
		queryResult = await res.json();
		console.log(queryResult);
	}
</script>

<style>
	.layout {
		display: flex;
		min-height: 100vh;
	}
	.explorer {
		background-color: #eff5f9;
		flex-basis: 270px;
		padding: 14px;
	}
	.main {
		flex-grow: 1;
		display: flex;
		flex-direction: column;
	}
	.query-input {
		flex-basis: 160px;
	}
	.query-result {
		flex-grow: 1;
	}
</style>

<div class="layout">
	<div class="explorer">
		{#if structure !== null}
			<Explorer structure={structure}/>
		{/if}
	</div>
	<div class="main">
		<div class="query-input">
			<QueryInput on:query={doQuery}/>
		</div>
		<div class="query-result">
			{#if queryResult !== null}
				<QueryResult result={queryResult}/>
			{/if}
		</div>
	</div>
</div>